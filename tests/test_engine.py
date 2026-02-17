"""Engine tests — mock OpenAI client, test tool-calling loop end-to-end."""

import json
import pytest
from unittest.mock import MagicMock, patch

from sysfox_ai.engine import DiagnosticEngine, trim_message_history, _parse_diagnosis_json
from sysfox_ai.models import DiagnoseRequest, Severity


class TestTrimMessageHistory:
    """Test message history trimming."""

    def test_no_trim_needed(self):
        messages = [{"role": "system", "content": "sys"}]
        messages += [{"role": "user", "content": f"msg {i}"} for i in range(10)]
        result = trim_message_history(messages)
        assert len(result) == 11  # system + 10

    def test_trim_large_history(self):
        messages = [{"role": "system", "content": "sys"}]
        messages += [{"role": "user", "content": f"msg {i}"} for i in range(100)]
        result = trim_message_history(messages)
        # system + notice + MAX_HISTORY_MESSAGES
        assert result[0]["role"] == "system"
        assert "trimmed" in result[1]["content"]

    def test_system_prompt_preserved(self):
        messages = [{"role": "system", "content": "SYSTEM PROMPT"}]
        messages += [{"role": "user", "content": f"msg {i}"} for i in range(100)]
        result = trim_message_history(messages)
        assert result[0]["content"] == "SYSTEM PROMPT"


class TestParseDiagnosisJSON:
    """Test JSON parsing from LLM responses."""

    def test_parse_json_block(self):
        text = '''Here is my analysis:
```json
{
    "findings": [{"severity": "HIGH", "component": "nginx", "server": "poc-lb", "summary": "test", "evidence": []}],
    "affected_components": ["nginx"],
    "root_cause": "nginx is down"
}
```'''
        result = _parse_diagnosis_json(text)
        assert result is not None
        assert result["root_cause"] == "nginx is down"
        assert len(result["findings"]) == 1

    def test_parse_bare_json(self):
        text = '{"findings": [], "affected_components": [], "root_cause": "all good"}'
        result = _parse_diagnosis_json(text)
        assert result is not None
        assert result["root_cause"] == "all good"

    def test_parse_no_json(self):
        text = "This is just plain text analysis with no JSON."
        result = _parse_diagnosis_json(text)
        assert result is None

    def test_parse_embedded_json(self):
        text = 'Based on my investigation, the diagnosis is: {"findings": [{"severity": "CRITICAL", "component": "postgresql", "server": "poc-postgresql", "summary": "DB down", "evidence": ["connection refused"]}], "affected_components": ["postgresql"], "root_cause": "PostgreSQL not running"}'
        result = _parse_diagnosis_json(text)
        assert result is not None
        assert result["root_cause"] == "PostgreSQL not running"


class TestDiagnosticEngine:
    """Test the diagnostic engine with mocked OpenAI client."""

    def _make_mock_response(self, content=None, tool_calls=None):
        """Create a mock OpenAI response."""
        msg = MagicMock()
        msg.content = content
        msg.tool_calls = tool_calls
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message = msg
        return response

    def _make_tool_call(self, name, arguments):
        """Create a mock tool call."""
        tc = MagicMock()
        tc.function.name = name
        tc.function.arguments = json.dumps(arguments)
        tc.id = f"call_{name}"
        return tc

    @patch("sysfox_ai.engine.build_system_prompt")
    def test_simple_diagnosis_no_tools(self, mock_prompt):
        mock_prompt.return_value = "system prompt"

        mock_client = MagicMock()
        diagnosis_json = json.dumps({
            "findings": [{
                "severity": "LOW",
                "component": "system",
                "server": "all",
                "summary": "All systems healthy",
                "evidence": ["all services running"]
            }],
            "affected_components": [],
            "root_cause": "No issues found"
        })
        mock_client.chat.completions.create.return_value = self._make_mock_response(
            content=f"```json\n{diagnosis_json}\n```"
        )

        engine = DiagnosticEngine(client=mock_client, ssh_pool=MagicMock())
        request = DiagnoseRequest(question="Is everything healthy?")
        result = engine.run(request)

        assert result.diagnosis_id
        assert result.question == "Is everything healthy?"
        assert result.root_cause == "No issues found"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW

    @patch("sysfox_ai.engine.dispatch_tool_call")
    @patch("sysfox_ai.engine.build_system_prompt")
    def test_diagnosis_with_tool_calls(self, mock_prompt, mock_dispatch):
        mock_prompt.return_value = "system prompt"
        mock_dispatch.return_value = ("[BEGIN OUTPUT]\nactive (running)\n[END OUTPUT]", "success")

        mock_client = MagicMock()

        # First response: tool call
        tool_call = self._make_tool_call(
            "check_service_status",
            {"server": "poc-lb", "service": "nginx"}
        )
        first_response = self._make_mock_response(
            content="Let me check nginx",
            tool_calls=[tool_call]
        )

        # Second response: final diagnosis
        diagnosis_json = json.dumps({
            "findings": [{
                "severity": "LOW",
                "component": "nginx_lb",
                "server": "poc-lb",
                "summary": "Nginx is running normally",
                "evidence": ["active (running)"]
            }],
            "affected_components": [],
            "root_cause": "No issues"
        })
        second_response = self._make_mock_response(
            content=f"```json\n{diagnosis_json}\n```"
        )

        mock_client.chat.completions.create.side_effect = [first_response, second_response]

        engine = DiagnosticEngine(client=mock_client, ssh_pool=MagicMock())
        request = DiagnoseRequest(question="Check nginx on LB")
        result = engine.run(request)

        assert result.steps_taken == 1
        assert len(result.reasoning_trace) > 0
        mock_dispatch.assert_called_once()

    @patch("sysfox_ai.engine.build_system_prompt")
    def test_max_steps_limit(self, mock_prompt):
        mock_prompt.return_value = "system prompt"

        mock_client = MagicMock()

        # Always return tool calls to test the step limit
        tool_call = self._make_tool_call(
            "run_command_on_server",
            {"server": "poc-lb", "command": "ps aux"}
        )
        tool_response = self._make_mock_response(
            content="Checking...",
            tool_calls=[tool_call]
        )
        mock_client.chat.completions.create.return_value = tool_response

        engine = DiagnosticEngine(client=mock_client, ssh_pool=MagicMock())

        with patch("sysfox_ai.engine.dispatch_tool_call") as mock_dispatch:
            mock_dispatch.return_value = ("output", "success")
            request = DiagnoseRequest(question="Test", max_steps=3)
            result = engine.run(request)

        assert result.steps_taken <= 3

    @patch("sysfox_ai.engine.build_system_prompt")
    def test_engine_error_handling(self, mock_prompt):
        mock_prompt.return_value = "system prompt"

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API error")

        engine = DiagnosticEngine(client=mock_client, ssh_pool=MagicMock())
        request = DiagnoseRequest(question="Test")
        result = engine.run(request)

        assert result.diagnosis_id
        assert "error" in result.root_cause.lower()
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    @patch("sysfox_ai.engine.build_system_prompt")
    def test_raw_text_fallback(self, mock_prompt):
        mock_prompt.return_value = "system prompt"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._make_mock_response(
            content="The system appears healthy based on my analysis."
        )

        engine = DiagnosticEngine(client=mock_client, ssh_pool=MagicMock())
        request = DiagnoseRequest(question="Health check")
        result = engine.run(request)

        # Should fall back to raw text as root cause
        assert "healthy" in result.root_cause.lower()
