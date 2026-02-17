"""Executor abstraction — command execution strategies.

Forked from sysadmin-ai Executor ABC + HostExecutor (as LocalExecutor).
New: SSHConnectionPool and SSHExecutor for remote dreamer servers.
"""

import os
import subprocess
import time
import logging
from abc import ABC, abstractmethod

import paramiko

from sysfox_ai.config import settings

logger = logging.getLogger("sysfox_ai")

MAX_OUTPUT_CHARS = settings.MAX_OUTPUT_CHARS
DEFAULT_COMMAND_TIMEOUT = settings.SSH_COMMAND_TIMEOUT


# --- Executor ABC (from sysadmin-ai L364-383) ---

class Executor(ABC):
    """Strategy interface for command execution."""

    @abstractmethod
    def execute(self, command, cwd=None, timeout=None):
        """Returns (output, status, new_cwd).

        Args:
            command: The shell command to run.
            cwd: Working directory for the command.
            timeout: Seconds before the command is killed.
        """
        ...

    def cleanup(self):
        pass


# --- LocalExecutor (from sysadmin-ai HostExecutor, stripped Windows/PowerShell) ---

class LocalExecutor(Executor):
    """Executes commands directly on the local host via subprocess."""

    _SENTINEL = "__SYSFOX_AI_PWD__"

    def execute(self, command, cwd=None, timeout=None):
        timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT

        wrapped = (
            f"{command}\n"
            f"__sa_exit=$?\n"
            f'if [ "$__sa_exit" -eq 0 ]; then echo {self._SENTINEL}_0; else echo {self._SENTINEL}_1; fi\n'
            f"pwd\n"
            f"exit $__sa_exit"
        )
        try:
            result = subprocess.run(
                wrapped, shell=True, capture_output=True, timeout=timeout,
                cwd=cwd, encoding="utf-8", errors="replace",
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            new_cwd = None
            cmd_failed = False

            if self._SENTINEL in stdout:
                before, _, after = stdout.partition(self._SENTINEL)
                lines = after.strip().split("\n")
                status_token = lines[0].strip() if lines else ""
                if status_token == "_1":
                    cmd_failed = True
                if len(lines) > 1:
                    pwd_line = lines[1].strip()
                    if pwd_line and os.path.isabs(pwd_line):
                        new_cwd = pwd_line
                stdout = before

            output = stdout + stderr
            if not output.strip():
                output = "(No output)"
            elif len(output) > MAX_OUTPUT_CHARS:
                output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} chars total)"

            status = "exit_1" if cmd_failed else "success"
            return output, status, new_cwd
        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after {timeout} seconds.", "timeout", None
        except Exception as e:
            return f"Error executing command: {str(e)}", "error", None


# --- SSH Connection Pool ---

class SSHConnectionPool:
    """Manages persistent paramiko SSH connections to dreamer servers.

    Provides connect_all(), get_connection(), execute(), close_all().
    Auto-reconnects on connection failure.
    """

    def __init__(self, servers, username=None, key_path=None,
                 connect_timeout=None, command_timeout=None):
        """
        Args:
            servers: dict of {hostname: ip_address}
            username: SSH username (default from settings)
            key_path: Path to SSH private key (default from settings)
            connect_timeout: Timeout for SSH connection (default from settings)
            command_timeout: Default timeout for command execution
        """
        self.servers = servers
        self.username = username or settings.SSH_USER
        self.key_path = key_path or settings.SSH_KEY_PATH
        self.connect_timeout = connect_timeout or settings.SSH_CONNECT_TIMEOUT
        self.command_timeout = command_timeout or settings.SSH_COMMAND_TIMEOUT
        self._connections: dict[str, paramiko.SSHClient] = {}
        self._pkey = None

    def _load_key(self):
        """Load the SSH private key."""
        if self._pkey is None:
            key_path = os.path.expanduser(self.key_path)
            self._pkey = paramiko.RSAKey.from_private_key_file(key_path)
        return self._pkey

    def _connect_one(self, hostname, ip):
        """Establish SSH connection to a single server."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip,
            username=self.username,
            pkey=self._load_key(),
            timeout=self.connect_timeout,
        )
        self._connections[hostname] = client
        logger.info(f"SSH connected to {hostname} ({ip})")
        return client

    def connect_all(self):
        """Connect to all servers. Returns dict of {hostname: connected_bool}."""
        results = {}
        for hostname, ip in self.servers.items():
            try:
                self._connect_one(hostname, ip)
                results[hostname] = True
            except Exception as e:
                logger.error(f"SSH connection failed for {hostname} ({ip}): {e}")
                results[hostname] = False
        return results

    def get_connection(self, hostname):
        """Get an active SSH connection, reconnecting if needed."""
        client = self._connections.get(hostname)
        if client is not None:
            transport = client.get_transport()
            if transport is not None and transport.is_active():
                return client
            # Connection is stale, try to reconnect
            logger.warning(f"SSH connection to {hostname} is stale, reconnecting...")

        ip = self.servers.get(hostname)
        if ip is None:
            raise ValueError(f"Unknown server: {hostname}")
        return self._connect_one(hostname, ip)

    def execute(self, hostname, command, timeout=None):
        """Execute a command on a specific server.

        Returns:
            (output, exit_code) tuple
        """
        timeout = timeout or self.command_timeout
        client = self.get_connection(hostname)

        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            output = out + err
            if not output.strip():
                output = "(No output)"
            elif len(output) > MAX_OUTPUT_CHARS:
                output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} chars total)"

            return output, exit_code
        except Exception as e:
            # Connection may have died — clear it so next call reconnects
            self._connections.pop(hostname, None)
            error_str = str(e)
            if "timed out" in error_str.lower() or "timeout" in error_str.lower():
                return f"Error: Command timed out after {timeout} seconds.", -1
            return f"Error executing command: {error_str}", -1

    def check_connectivity(self):
        """Check SSH connectivity to all servers. Returns {hostname: bool}."""
        results = {}
        for hostname in self.servers:
            try:
                client = self.get_connection(hostname)
                transport = client.get_transport()
                results[hostname] = transport is not None and transport.is_active()
            except Exception:
                results[hostname] = False
        return results

    def close_all(self):
        """Close all SSH connections."""
        for hostname, client in self._connections.items():
            try:
                client.close()
                logger.info(f"SSH disconnected from {hostname}")
            except Exception:
                pass
        self._connections.clear()


# --- SSHExecutor ---

class SSHExecutor(Executor):
    """Executor that wraps SSHConnectionPool for a specific target server."""

    def __init__(self, pool, hostname):
        self.pool = pool
        self.hostname = hostname

    def execute(self, command, cwd=None, timeout=None):
        """Execute a command on the target server via SSH.

        Returns (output, status, None) — no CWD tracking (stateless SSH).
        """
        if cwd:
            command = f"cd {cwd} && {command}"

        output, exit_code = self.pool.execute(self.hostname, command, timeout=timeout)
        status = "success" if exit_code == 0 else "error"
        return output, status, None

    def cleanup(self):
        pass  # Pool manages connections
