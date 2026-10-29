"""Adapters that transform event telemetry from major agent frameworks into Assay events."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping, Optional

from .errors import ValidationError
from .model import Event, OUTCOMES, normalize_timestamp


def _value(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        val = row.get(name)
        if val is not None and val != "":
            return val
    return default


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        val = value.strip()
        if (val.startswith("{") and val.endswith("}")) or (val.startswith("[") and val.endswith("]")):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, Mapping):
                    return dict(parsed)
                return {"content": parsed}
            except json.JSONDecodeError:
                # hygiene: allow string is preserved as verbatim content when JSON decoding fails
                return {"content": value}
        return {"content": value}
    if value is None:
        return {}
    return {"value": value}


def generic_event(row: Mapping[str, Any], actor_default: Optional[str] = None,
                  policy_ref: Optional[Dict[str, str]] = None) -> Event:
    """Transform standard generic JSON into an Assay Event."""
    actor = _value(row, "actor", "agent", "actor_id", "principal", default=actor_default)
    action = _value(row, "action", "tool", "name", "operation")
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "An ingested record has no actor.",
            "every action must name the agent or principal that performed it.",
            "add an actor field or pass --actor as the fallback.",
        )
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "An ingested record has no action or tool name.",
            "a record without an action cannot be audited or matched by a policy.",
            "add action/tool/name, or fix the producer mapping.",
        )
    raw_outcome = _value(row, "outcome", "status", default="success")
    if not isinstance(raw_outcome, str):
        raise ValidationError(
            f"Unrecognized outcome {raw_outcome!r}.",
            f"the event contract allows: {', '.join(OUTCOMES)}.",
            "fix the producer outcome or map it explicitly.",
        )
    outcome = raw_outcome.strip().lower()
    if outcome not in OUTCOMES:
        raise ValidationError(
            f"Unknown outcome '{raw_outcome}'.",
            f"the event contract allows: {', '.join(OUTCOMES)}.",
            "fix the producer outcome or map it explicitly.",
        )
    metadata = _value(row, "metadata", "arguments", "input", default={})
    if not isinstance(metadata, Mapping):
        metadata = _as_dict(metadata)
    else:
        metadata = dict(metadata)
    ts = _value(row, "ts", "timestamp", "time")
    return Event.create(
        actor, action,
        outcome=outcome,
        target=_value(row, "target", "resource", "destination", default=""),
        metadata=metadata,
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


def mcp_event(row: Mapping[str, Any], actor_default: Optional[str] = None,
              policy_ref: Optional[Dict[str, str]] = None) -> Optional[Event]:
    """Transform Model Context Protocol (MCP) JSON-RPC messages into an Event."""
    method = row.get("method")
    if method is not None and method != "tools/call":
        return None
    params = row.get("params")
    params = params if isinstance(params, Mapping) else {}
    action = params.get("name") or row.get("tool") or row.get("name") or row.get("action")
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "An MCP tools/call record has no tool name.",
            "the tool name is the audited action.",
            "fix the producer or use --format generic with an explicit mapping.",
        )
    actor = _value(row, "actor", "agent", default=actor_default)
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "An MCP record has no actor.",
            "tool calls need a principal, even when the server log omits one.",
            "pass --actor for the session.",
        )
    result = row.get("result")
    outcome = "error" if isinstance(result, Mapping) and result.get("isError") else "success"
    metadata = params.get("arguments")
    if not isinstance(metadata, Mapping):
        metadata = _as_dict(metadata)
    else:
        metadata = dict(metadata)
    if result is not None and isinstance(result, Mapping):
        if "content" in result and "content" not in metadata:
            metadata["content"] = result["content"]
    ts = _value(row, "ts", "timestamp", "time")
    return Event.create(
        actor, action,
        outcome=outcome,
        metadata=metadata,
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


def openai_event(row: Mapping[str, Any], actor_default: Optional[str] = None,
                 policy_ref: Optional[Dict[str, str]] = None) -> Optional[Event]:
    """Transform OpenAI tool calls and assistant execution telemetry into an Event."""
    fn = row.get("function")
    fn = fn if isinstance(fn, Mapping) else {}
    action = fn.get("name") or row.get("name") or row.get("action") or row.get("tool")
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "An OpenAI tool call record has no function or tool name.",
            "the tool name is the audited action.",
            "ensure the record has function.name, name, or action.",
        )
    actor = _value(row, "actor", "agent", "role", default=actor_default)
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "An OpenAI record has no actor.",
            "tool calls need a principal, even when the API payload omits one.",
            "pass --actor for the session or include actor in the record.",
        )
    raw_args = fn.get("arguments") if "arguments" in fn else row.get("arguments")
    metadata = _as_dict(raw_args)
    tool_call_id = row.get("id") or row.get("tool_call_id")
    if tool_call_id and isinstance(tool_call_id, str):
        metadata["tool_call_id"] = tool_call_id
    if "output" in row and "output" not in metadata:
        metadata["output"] = row["output"]
    if "error" in row:
        metadata["error"] = row["error"]
        outcome = "error"
    elif row.get("status") in ("failed", "error"):
        outcome = "error"
    else:
        raw_outcome = _value(row, "outcome", "status", default="success")
        outcome = raw_outcome.lower() if isinstance(raw_outcome, str) and raw_outcome in OUTCOMES else "success"
    ts = _value(row, "ts", "timestamp", "time", "created_at")
    return Event.create(
        actor, action,
        outcome=outcome,
        target=_value(row, "target", "resource", default=""),
        metadata=metadata,
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


def langgraph_event(row: Mapping[str, Any], actor_default: Optional[str] = None,
                    policy_ref: Optional[Dict[str, str]] = None) -> Optional[Event]:
    """Transform LangChain and LangGraph node/tool event records into an Event."""
    data = row.get("data")
    data = data if isinstance(data, Mapping) else {}
    action = row.get("name") or data.get("name") or row.get("tool") or row.get("action")
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "A LangGraph event record has no tool or action name.",
            "every event must declare the tool or step executed.",
            "ensure the record has name, tool, or action.",
        )
    actor = _value(row, "actor", "agent", "node", default=actor_default)
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "A LangGraph record has no actor.",
            "tool executions must identify the agent, chain or graph node.",
            "pass --actor for the session or set actor in the event.",
        )
    metadata: Dict[str, Any] = {}
    inp = data.get("input") if "input" in data else row.get("args") or row.get("input")
    if inp is not None:
        if isinstance(inp, Mapping):
            metadata.update(inp)
        else:
            metadata["input"] = inp
    outp = data.get("output") if "output" in data else row.get("output")
    if outp is not None:
        metadata["output"] = outp
    content = row.get("content")
    if content is not None:
        metadata["content"] = _as_dict(content) if isinstance(content, str) and content.strip().startswith("{") else content
    tool_call_id = row.get("tool_call_id") or row.get("id")
    if tool_call_id and isinstance(tool_call_id, str):
        metadata["tool_call_id"] = tool_call_id
    if "error" in row or "error" in data:
        outcome = "error"
        err_val = row.get("error") or data.get("error")
        if err_val:
            metadata["error"] = err_val
    else:
        raw_outcome = _value(row, "outcome", "status", default="success")
        outcome = raw_outcome.lower() if isinstance(raw_outcome, str) and raw_outcome in OUTCOMES else "success"
    ts = _value(row, "ts", "timestamp", "time")
    return Event.create(
        actor, action,
        outcome=outcome,
        target=_value(row, "target", "resource", default=""),
        metadata=metadata,
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


def crewai_event(row: Mapping[str, Any], actor_default: Optional[str] = None,
                 policy_ref: Optional[Dict[str, str]] = None) -> Optional[Event]:
    """Transform CrewAI tool execution and agent action dictionaries into an Event."""
    action = row.get("tool") or row.get("action") or row.get("task")
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "A CrewAI event record has no tool, action, or task name.",
            "the action name identifies what the agent executed.",
            "ensure the record has tool, action, or task.",
        )
    actor = _value(row, "agent", "agent_role", "actor", default=actor_default)
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "A CrewAI record has no actor.",
            "every action must name the agent or role that performed it.",
            "pass --actor for the session or set agent in the record.",
        )
    metadata: Dict[str, Any] = {}
    tool_input = row.get("tool_input") if "tool_input" in row else row.get("action_input")
    if tool_input is not None:
        if isinstance(tool_input, Mapping):
            metadata.update(tool_input)
        else:
            metadata["input"] = tool_input
    result = row.get("result") if "result" in row else row.get("output")
    if result is not None:
        metadata["result"] = result
    if "thought" in row and isinstance(row["thought"], str):
        metadata["thought"] = row["thought"]
    if "error" in row:
        outcome = "error"
        metadata["error"] = row["error"]
    else:
        raw_outcome = _value(row, "outcome", "status", default="success")
        outcome = raw_outcome.lower() if isinstance(raw_outcome, str) and raw_outcome in OUTCOMES else "success"
    ts = _value(row, "ts", "timestamp", "time")
    return Event.create(
        actor, action,
        outcome=outcome,
        target=_value(row, "target", "resource", default=""),
        metadata=metadata,
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


ADAPTERS: Dict[str, Callable[[Mapping[str, Any], Optional[str], Optional[Dict[str, str]]], Optional[Event]]] = {
    "generic": generic_event,
    "mcp": mcp_event,
    "openai": openai_event,
    "langgraph": langgraph_event,
    "crewai": crewai_event,
}


def adapt_event(format_name: str, row: Mapping[str, Any],
                actor_default: Optional[str] = None,
                policy_ref: Optional[Dict[str, str]] = None) -> Optional[Event]:
    """Transform a dictionary from a named framework into an Event."""
    adapter = ADAPTERS.get(format_name)
    if adapter is None:
        raise ValidationError(
            f"Unknown adapter format '{format_name}'.",
            f"supported formats are: {', '.join(sorted(ADAPTERS))}.",
            "select a supported adapter format.",
        )
    return adapter(row, actor_default, policy_ref)


def parse_event_stream(text: str, format_name: str,
                       actor_default: Optional[str] = None,
                       policy_ref: Optional[Dict[str, str]] = None) -> List[Event]:
    """Parse JSONL stream using the selected framework adapter."""
    events: List[Event] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"Input line {number} is not valid JSON: {exc.msg}.",
                "the whole file is validated before any event is appended.",
                "fix the producer output and retry; nothing was written.",
            ) from exc
        if not isinstance(row, Mapping):
            raise ValidationError(
                f"Input line {number} is not a JSON object.",
                "each JSONL line must describe one action.",
                "fix the producer output and retry; nothing was written.",
            )
        event = adapt_event(format_name, row, actor_default, policy_ref)
        if event is not None:
            events.append(event)
    if not events:
        raise ValidationError(
            "No events were found in the input.",
            "an empty ingest would produce an empty evidence trail.",
            "check the file and adapter, then retry.",
        )
    return events
