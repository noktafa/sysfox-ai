"""Diagnostic engine — LLM tool-calling loop.

Forked from sysadmin-ai chat_loop (L1308-1518). Adapted for:
- Bounded loop (max N steps, not infinite REPL)
- Graylist auto-reject (no interactive confirmation)
- Structured DiagnoseResponse output
- Per-request state (no persistent shell state)
"""

import json
import time
import uuid
import logging

from openai import OpenAI

from sysfox_ai.config import settings
from sysfox_ai.models import DiagnoseRequest, DiagnoseResponse, DiagnosticFinding, Severity
from sysfox_ai.tools import tools as tool_schemas, dispatch_tool_call
from sysfox_ai.prompts import build_system_prompt
from sysfox_ai.logging_config import log_event

logger = logging.getLogger("sysfox_ai")

MAX_HISTORY_MESSAGES = settings.MAX_HISTORY_MESSAGES


def trim_message_history(messages):
    """Trim old messages to stay within context limits.

    Keeps:
      - messages[0]: system prompt (always)
      - The most recent MAX_HISTORY_MESSAGES messages

    When messages are trimmed a short notice is injected so the LLM
    knows prior context was dropped.
    """
    if len(messages) <= MAX_HISTORY_MESSAGES + 1:
        return messages

    system = messages[0]
    recent = messages[-(MAX_HISTORY_MESSAGES):]

    trimmed_count = len(messages) - 1 - MAX_HISTORY_MESSAGES
    notice = {
        "role": "user",
        "content": (
            f"[Note: {trimmed_count} older messages were trimmed to stay "
            "within context limits. Recent conversation follows.]"
        ),
    }
    return [system, notice] + recent


def _parse_diagnosis_json(text):
    """Extract JSON diagnosis from the LLM's final response.

    Tries to find a JSON block in the text. Falls back to raw text.
    """
    # Try to extract JSON from markdown code block
    import re
    json_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try the entire text as JSON
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # Try to find a bare JSON object
    json_match = re.search(r"(\{[\s\S]*\"findings\"[\s\S]*\})", text)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    return None


class DiagnosticEngine:
    """Runs a bounded diagnostic loop using LLM tool-calling."""

    def __init__(self, client: OpenAI, ssh_pool):
        self.client = client
        self.model = settings.OPENAI_MODEL
        self.ssh_pool = ssh_pool

    def run(self, request: DiagnoseRequest) -> DiagnoseResponse:
        """Execute a diagnostic session.

        Args:
            request: The diagnosis request with question, scope, max_steps.

        Returns:
            Structured DiagnoseResponse.
        """
        start_time = time.time()
        diagnosis_id = str(uuid.uuid4())
        reasoning_trace = []
        steps_taken = 0

        system_prompt = build_system_prompt(scope=request.scope)
        scope_text = ""
        if request.scope:
            if request.scope.servers:
                scope_text += f"\nFocus on servers: {request.scope.servers}"
            if request.scope.components:
                scope_text += f"\nFocus on components: {request.scope.components}"
            if request.scope.time_range:
                scope_text += f"\nTime range: {request.scope.time_range}"

        user_message = f"Diagnose the following issue:\n\n{request.question}"
        if scope_text:
            user_message += f"\n\nScope:{scope_text}"
        if request.correlation_id:
            user_message += f"\n\nCorrelation ID to trace: {request.correlation_id}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        log_event("diagnosis_start", {
            "diagnosis_id": diagnosis_id,
            "question": request.question,
            "max_steps": request.max_steps,
        })

        try:
            messages = trim_message_history(messages)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tool_schemas,
                tool_choice="auto",
            )
            msg = response.choices[0].message
            messages.append(msg)

            while msg.tool_calls and steps_taken < request.max_steps:
                reasoning = msg.content or ""
                if reasoning:
                    reasoning_trace.append(f"Step {steps_taken + 1}: {reasoning}")

                for tool_call in msg.tool_calls:
                    steps_taken += 1
                    tool_name = tool_call.function.name
                    try:
                        tool_args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        tool_args = {}

                    log_event("tool_call", {
                        "diagnosis_id": diagnosis_id,
                        "tool": tool_name,
                        "args": tool_args,
                        "step": steps_taken,
                    })

                    result_text, status = dispatch_tool_call(
                        tool_name, tool_args, self.ssh_pool
                    )

                    reasoning_trace.append(
                        f"Tool: {tool_name}({json.dumps(tool_args)}) → {status}"
                    )

                    log_event("tool_result", {
                        "diagnosis_id": diagnosis_id,
                        "tool": tool_name,
                        "status": status,
                        "step": steps_taken,
                    })

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result_text,
                    })

                messages = trim_message_history(messages)
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=tool_schemas,
                    tool_choice="auto",
                )
                msg = response.choices[0].message
                messages.append(msg)

        except Exception as e:
            logger.error(f"Diagnostic engine error: {e}", exc_info=True)
            duration = time.time() - start_time
            return DiagnoseResponse(
                diagnosis_id=diagnosis_id,
                question=request.question,
                findings=[DiagnosticFinding(
                    severity=Severity.HIGH,
                    component="sysfox-ai",
                    server="local",
                    summary=f"Diagnostic engine error: {type(e).__name__}: {e}",
                    evidence=[],
                )],
                root_cause=f"Engine error: {e}",
                reasoning_trace=reasoning_trace,
                llm_model=self.model,
                steps_taken=steps_taken,
                duration_seconds=round(duration, 2),
            )

        # Parse the final response into structured output
        duration = time.time() - start_time
        final_text = msg.content or ""

        diagnosis_data = _parse_diagnosis_json(final_text)

        findings = []
        affected_components = []
        root_cause = ""

        if diagnosis_data:
            for f in diagnosis_data.get("findings", []):
                try:
                    findings.append(DiagnosticFinding(
                        severity=Severity(f.get("severity", "MEDIUM")),
                        component=f.get("component", "unknown"),
                        server=f.get("server", "unknown"),
                        summary=f.get("summary", ""),
                        evidence=f.get("evidence", []),
                    ))
                except (ValueError, KeyError):
                    findings.append(DiagnosticFinding(
                        severity=Severity.MEDIUM,
                        component=f.get("component", "unknown"),
                        server=f.get("server", "unknown"),
                        summary=f.get("summary", str(f)),
                        evidence=f.get("evidence", []),
                    ))
            affected_components = diagnosis_data.get("affected_components", [])
            root_cause = diagnosis_data.get("root_cause", "")
        else:
            # Fallback: use raw text as root cause
            root_cause = final_text
            if final_text:
                reasoning_trace.append(f"Final response (raw): {final_text[:500]}")

        log_event("diagnosis_complete", {
            "diagnosis_id": diagnosis_id,
            "steps_taken": steps_taken,
            "findings_count": len(findings),
            "duration_seconds": round(duration, 2),
        })

        return DiagnoseResponse(
            diagnosis_id=diagnosis_id,
            question=request.question,
            findings=findings,
            affected_components=affected_components,
            root_cause=root_cause,
            reasoning_trace=reasoning_trace,
            llm_model=self.model,
            steps_taken=steps_taken,
            duration_seconds=round(duration, 2),
        )
