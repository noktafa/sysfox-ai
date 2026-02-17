"""Executor tests — mock paramiko for SSHExecutor and SSHConnectionPool."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from sysfox_ai.executor import SSHConnectionPool, SSHExecutor, LocalExecutor


class TestSSHConnectionPool:
    """Test SSHConnectionPool with mocked paramiko."""

    @patch("sysfox_ai.executor.paramiko")
    def test_connect_all_success(self, mock_paramiko):
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4", "poc-app1": "5.6.7.8"},
            key_path="/fake/key",
        )
        results = pool.connect_all()

        assert results["poc-lb"] is True
        assert results["poc-app1"] is True
        assert mock_client.connect.call_count == 2

    @patch("sysfox_ai.executor.paramiko")
    def test_connect_failure(self, mock_paramiko):
        mock_client = MagicMock()
        mock_client.connect.side_effect = Exception("Connection refused")
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4"},
            key_path="/fake/key",
        )
        results = pool.connect_all()

        assert results["poc-lb"] is False

    @patch("sysfox_ai.executor.paramiko")
    def test_execute_success(self, mock_paramiko):
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"output data\n"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4"},
            key_path="/fake/key",
        )
        pool.connect_all()
        output, exit_code = pool.execute("poc-lb", "ps aux")

        assert "output data" in output
        assert exit_code == 0

    @patch("sysfox_ai.executor.paramiko")
    def test_execute_with_error(self, mock_paramiko):
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 1
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b"command not found\n"
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4"},
            key_path="/fake/key",
        )
        pool.connect_all()
        output, exit_code = pool.execute("poc-lb", "nonexistent_cmd")

        assert "command not found" in output
        assert exit_code == 1

    def test_unknown_server(self):
        pool = SSHConnectionPool(servers={"poc-lb": "1.2.3.4"})
        with pytest.raises(ValueError, match="Unknown server"):
            pool.get_connection("nonexistent")

    @patch("sysfox_ai.executor.paramiko")
    def test_reconnect_on_stale(self, mock_paramiko):
        mock_stale_client = MagicMock()
        # Stale transport
        mock_transport_stale = MagicMock()
        mock_transport_stale.is_active.return_value = False
        mock_stale_client.get_transport.return_value = mock_transport_stale

        mock_new_client = MagicMock()
        # SSHClient() is called during _connect_one for reconnection
        mock_paramiko.SSHClient.return_value = mock_new_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4"},
            key_path="/fake/key",
        )
        # Manually inject the stale connection
        pool._connections["poc-lb"] = mock_stale_client

        # Should reconnect and return the new client
        result = pool.get_connection("poc-lb")
        assert result == mock_new_client
        mock_new_client.connect.assert_called_once()

    @patch("sysfox_ai.executor.paramiko")
    def test_close_all(self, mock_paramiko):
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4"},
            key_path="/fake/key",
        )
        pool.connect_all()
        pool.close_all()

        mock_client.close.assert_called_once()
        assert len(pool._connections) == 0

    @patch("sysfox_ai.executor.paramiko")
    def test_check_connectivity(self, mock_paramiko):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4", "poc-app1": "5.6.7.8"},
            key_path="/fake/key",
        )
        pool.connect_all()
        status = pool.check_connectivity()

        assert status["poc-lb"] is True
        assert status["poc-app1"] is True

    @patch("sysfox_ai.executor.paramiko")
    def test_output_truncation(self, mock_paramiko):
        mock_client = MagicMock()
        # Return a very large output
        large_output = "x" * 10000
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = large_output.encode()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.RSAKey.from_private_key_file.return_value = MagicMock()

        pool = SSHConnectionPool(
            servers={"poc-lb": "1.2.3.4"},
            key_path="/fake/key",
        )
        pool.connect_all()
        output, exit_code = pool.execute("poc-lb", "generate_large_output")

        assert "truncated" in output
        assert exit_code == 0


class TestSSHExecutor:
    """Test SSHExecutor wrapper."""

    def test_execute_delegates_to_pool(self):
        mock_pool = MagicMock()
        mock_pool.execute.return_value = ("output", 0)

        executor = SSHExecutor(mock_pool, "poc-lb")
        output, status, cwd = executor.execute("ps aux")

        mock_pool.execute.assert_called_once_with("poc-lb", "ps aux", timeout=None)
        assert output == "output"
        assert status == "success"
        assert cwd is None

    def test_execute_with_cwd(self):
        mock_pool = MagicMock()
        mock_pool.execute.return_value = ("output", 0)

        executor = SSHExecutor(mock_pool, "poc-lb")
        executor.execute("ls", cwd="/var/log")

        mock_pool.execute.assert_called_once_with(
            "poc-lb", "cd /var/log && ls", timeout=None
        )

    def test_execute_error_status(self):
        mock_pool = MagicMock()
        mock_pool.execute.return_value = ("error output", 1)

        executor = SSHExecutor(mock_pool, "poc-lb")
        output, status, cwd = executor.execute("failing_cmd")

        assert status == "error"


class TestLocalExecutor:
    """Test LocalExecutor (subprocess-based)."""

    def test_execute_simple_command(self):
        executor = LocalExecutor()
        output, status, cwd = executor.execute("echo hello")
        assert "hello" in output
        assert status == "success"

    def test_execute_failing_command(self):
        executor = LocalExecutor()
        output, status, cwd = executor.execute("false")
        assert status == "exit_1"

    def test_execute_timeout(self):
        executor = LocalExecutor()
        output, status, cwd = executor.execute("sleep 10", timeout=1)
        assert status == "timeout"
        assert "timed out" in output
