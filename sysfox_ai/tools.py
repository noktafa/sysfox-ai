"""LLM tool schemas and dispatch logic.

5 diagnostic tools (replaces sysadmin-ai's 3):
- run_command_on_server
- read_file_on_server
- query_elk_logs
- check_service_status
- check_connectivity

No write_file tool. All tools include a server parameter.
"""

import json
import logging

from sysfox_ai.safety import check_command_safety, _check_read_safety, redact_text
from sysfox_ai.inventory import SERVER_HOSTNAMES, SERVERS

logger = logging.getLogger("sysfox_ai")

# --- Tool schemas for OpenAI function calling ---

tools = [
    {
        "type": "function",
        "function": {
            "name": "run_command_on_server",
            "description": (
                "Execute a read-only shell command on a specific dreamer server via SSH. "
                "Use for inspecting processes, checking disk, viewing logs, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "enum": SERVER_HOSTNAMES,
                        "description": "The target server hostname."
                    },
                    "command": {
                        "type": "string",
                        "description": (
                            "The shell command to execute. Must be read-only/diagnostic. "
                            "e.g., 'ps aux', 'df -h', 'tail -100 /var/log/syslog', 'netstat -tlnp'"
                        )
                    }
                },
                "required": ["server", "command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file_on_server",
            "description": (
                "Read the contents of a file on a specific dreamer server. "
                "Safer than cat — checks read safety and handles encoding. "
                "Use for config files, logs, and application files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "enum": SERVER_HOSTNAMES,
                        "description": "The target server hostname."
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file to read."
                    },
                    "tail_lines": {
                        "type": "integer",
                        "description": "If set, only read the last N lines (useful for large logs)."
                    }
                },
                "required": ["server", "path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_elk_logs",
            "description": (
                "Query Elasticsearch on poc-elk for structured log data. "
                "Supports filtering by time range, severity, component, correlation ID, and keywords."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "description": "Time range for the query, e.g., 'last 1 hour', 'last 30 minutes', 'last 2 days'. Default: 'last 1 hour'."
                    },
                    "severity": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by log severity levels, e.g., ['ERROR', 'WARNING']."
                    },
                    "components": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by component names, e.g., ['nginx_lb', 'app', 'postgresql']."
                    },
                    "correlation_id": {
                        "type": "string",
                        "description": "Filter by a specific correlation ID to trace a request across components."
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Search for specific keywords in log messages."
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of log entries to return. Default: 50."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_service_status",
            "description": (
                "Check the status of a systemd service on a dreamer server. "
                "Returns systemctl status output and recent journal entries."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "enum": SERVER_HOSTNAMES,
                        "description": "The target server hostname."
                    },
                    "service": {
                        "type": "string",
                        "description": "The systemd service name, e.g., 'nginx', 'postgresql', 'rabbitmq-server', 'dreamer-app'."
                    }
                },
                "required": ["server", "service"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_connectivity",
            "description": (
                "Test TCP connectivity from one dreamer server to another on a specific port. "
                "Useful for diagnosing network issues between components."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "from_server": {
                        "type": "string",
                        "enum": SERVER_HOSTNAMES,
                        "description": "The server to test connectivity FROM."
                    },
                    "to_server": {
                        "type": "string",
                        "enum": SERVER_HOSTNAMES,
                        "description": "The server to test connectivity TO."
                    },
                    "port": {
                        "type": "integer",
                        "description": "The TCP port to test."
                    }
                },
                "required": ["from_server", "to_server", "port"]
            }
        }
    },
]


def _wrap_tool_output(tool_name, output):
    """Wrap tool output in delimiters to mitigate prompt injection.

    Command output is untrusted data — wrapping it in clear delimiters
    helps the LLM distinguish data from instructions.
    """
    return f"[BEGIN {tool_name} OUTPUT]\n{output}\n[END {tool_name} OUTPUT]"


def _parse_time_range(time_range):
    """Parse a human-readable time range into ES 'now-Xh' format."""
    import re
    match = re.search(r"(\d+)\s*(hour|minute|min|day)", time_range.lower())
    if match:
        value = int(match.group(1))
        unit = match.group(2)
        if unit.startswith("hour"):
            return f"now-{value}h"
        elif unit.startswith("min"):
            return f"now-{value}m"
        elif unit.startswith("day"):
            return f"now-{value}d"
    return "now-1h"


def _build_elk_query(args):
    """Build an Elasticsearch query body from tool arguments."""
    must_filters = []

    time_range = args.get("time_range", "last 1 hour")
    must_filters.append({"range": {"@timestamp": {"gte": _parse_time_range(time_range)}}})

    severity = args.get("severity", [])
    if severity:
        must_filters.append({"terms": {"log_data.level": severity}})

    components = args.get("components", [])
    if components:
        must_filters.append({"terms": {"component": components}})

    cid = args.get("correlation_id")
    if cid:
        must_filters.append({"term": {"correlation_id": cid}})

    should_clauses = []
    keywords = args.get("keywords", [])
    for kw in keywords:
        should_clauses.append({"match": {"message": kw}})

    max_results = args.get("max_results", 50)

    query_body = {
        "query": {
            "bool": {
                "filter": must_filters,
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": max_results,
        "aggs": {
            "errors_by_component": {
                "filter": {"term": {"log_data.level": "ERROR"}},
                "aggs": {
                    "components": {"terms": {"field": "component", "size": 20}},
                },
            },
            "logs_over_time": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1m"},
            },
        },
    }

    if should_clauses:
        query_body["query"]["bool"]["should"] = should_clauses
        query_body["query"]["bool"]["minimum_should_match"] = 1

    return json.dumps(query_body)


def dispatch_tool_call(tool_name, tool_args, ssh_pool):
    """Dispatch a tool call to the appropriate handler.

    Args:
        tool_name: The function name from the LLM tool call.
        tool_args: Parsed arguments dict.
        ssh_pool: SSHConnectionPool instance.

    Returns:
        (result_text, status) tuple.
    """
    if tool_name == "run_command_on_server":
        server = tool_args.get("server", "")
        command = tool_args.get("command", "")

        if server not in SERVER_HOSTNAMES:
            return f"Error: Unknown server '{server}'. Valid: {SERVER_HOSTNAMES}", "error"

        # Safety check
        safety, reason = check_command_safety(command)
        if safety == "blocked":
            return f"BLOCKED: Command rejected by safety filter — {reason}. Do NOT attempt this command again.", "blocked"
        if safety == "confirm":
            return (
                f"REJECTED: Command '{command}' requires interactive confirmation ({reason}) "
                "which is not available in API mode. Use a safer alternative."
            ), "graylist"

        output, exit_code = ssh_pool.execute(server, command)
        output = redact_text(output)
        return _wrap_tool_output(tool_name, output), "success" if exit_code == 0 else "error"

    elif tool_name == "read_file_on_server":
        server = tool_args.get("server", "")
        path = tool_args.get("path", "")
        tail_lines = tool_args.get("tail_lines")

        if server not in SERVER_HOSTNAMES:
            return f"Error: Unknown server '{server}'. Valid: {SERVER_HOSTNAMES}", "error"

        # Safety check on path
        safety, reason = _check_read_safety(path)
        if safety == "blocked":
            return f"BLOCKED: {reason}", "blocked"

        if tail_lines:
            command = f"tail -n {int(tail_lines)} {path}"
        else:
            command = f"cat {path}"

        output, exit_code = ssh_pool.execute(server, command)
        output = redact_text(output)
        return _wrap_tool_output(tool_name, output), "success" if exit_code == 0 else "error"

    elif tool_name == "query_elk_logs":
        elk_query = _build_elk_query(tool_args)
        # Execute the ES query via curl on poc-elk
        command = (
            f"curl -s -X GET 'http://localhost:9200/dreamer-logs-*/_search' "
            f"-H 'Content-Type: application/json' -d '{elk_query}'"
        )

        # Safety check (curl to localhost is safe)
        safety, reason = check_command_safety(command)
        if safety == "blocked":
            return f"BLOCKED: {reason}", "blocked"

        output, exit_code = ssh_pool.execute("poc-elk", command)
        output = redact_text(output)
        return _wrap_tool_output(tool_name, output), "success" if exit_code == 0 else "error"

    elif tool_name == "check_service_status":
        server = tool_args.get("server", "")
        service = tool_args.get("service", "")

        if server not in SERVER_HOSTNAMES:
            return f"Error: Unknown server '{server}'. Valid: {SERVER_HOSTNAMES}", "error"

        command = f"systemctl status {service} --no-pager 2>&1; echo '---JOURNAL---'; journalctl -u {service} -n 20 --no-pager 2>&1"
        output, exit_code = ssh_pool.execute(server, command)
        output = redact_text(output)
        # systemctl status returns exit 3 for inactive services — not an error
        return _wrap_tool_output(tool_name, output), "success"

    elif tool_name == "check_connectivity":
        from_server = tool_args.get("from_server", "")
        to_server = tool_args.get("to_server", "")
        port = tool_args.get("port", 0)

        if from_server not in SERVER_HOSTNAMES:
            return f"Error: Unknown server '{from_server}'. Valid: {SERVER_HOSTNAMES}", "error"
        if to_server not in SERVER_HOSTNAMES:
            return f"Error: Unknown server '{to_server}'. Valid: {SERVER_HOSTNAMES}", "error"

        target_ip = SERVERS[to_server].private_ip
        command = (
            f"timeout 5 bash -c 'echo > /dev/tcp/{target_ip}/{port}' 2>&1 "
            f"&& echo 'CONNECTION_OK: {from_server} -> {to_server}:{port}' "
            f"|| echo 'CONNECTION_FAILED: {from_server} -> {to_server}:{port}'"
        )
        output, exit_code = ssh_pool.execute(from_server, command)
        output = redact_text(output)
        return _wrap_tool_output(tool_name, output), "success"

    else:
        return f"Error: Unknown tool '{tool_name}'", "error"
