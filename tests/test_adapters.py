"""Agent framework adapter tests for MCP, OpenAI, LangGraph, and CrewAI."""

import json
import unittest

from assay.adapters import (
    ADAPTERS,
    adapt_event,
    crewai_event,
    generic_event,
    langgraph_event,
    mcp_event,
    openai_event,
    parse_event_stream,
)
from assay.errors import ValidationError


class GenericAdapterTests(unittest.TestCase):
    def test_standard_keys(self):
        row = {
            "actor": "agent:test",
            "action": "files.read",
            "outcome": "success",
            "target": "/etc/hosts",
            "metadata": {"bytes": 42},
            "ts": "2026-10-24T10:00:00Z",
        }
        event = generic_event(row)
        self.assertEqual(event.actor, "agent:test")
        self.assertEqual(event.action, "files.read")
        self.assertEqual(event.target, "/etc/hosts")
        self.assertEqual(event.metadata["bytes"], 42)

    def test_alternate_field_names(self):
        row = {
            "agent": "worker-1",
            "tool": "calculator",
            "input": {"expression": "2+2"},
        }
        event = generic_event(row)
        self.assertEqual(event.actor, "worker-1")
        self.assertEqual(event.action, "calculator")
        self.assertEqual(event.metadata["expression"], "2+2")

    def test_missing_actor_raises(self):
        with self.assertRaises(ValidationError):
            generic_event({"action": "ping"})

    def test_actor_fallback(self):
        event = generic_event({"action": "ping"}, actor_default="fallback:agent")
        self.assertEqual(event.actor, "fallback:agent")


class McpAdapterTests(unittest.TestCase):
    def test_tools_call_event(self):
        row = {
            "method": "tools/call",
            "params": {"name": "query_database", "arguments": {"query": "SELECT 1"}},
            "actor": "agent:db-bot",
        }
        event = mcp_event(row)
        self.assertIsNotNone(event)
        self.assertEqual(event.actor, "agent:db-bot")
        self.assertEqual(event.action, "query_database")
        self.assertEqual(event.metadata["query"], "SELECT 1")
        self.assertEqual(event.outcome, "success")

    def test_non_tool_call_returns_none(self):
        row = {"method": "notifications/initialized"}
        self.assertIsNone(mcp_event(row))

    def test_error_result(self):
        row = {
            "method": "tools/call",
            "params": {"name": "fail_tool", "arguments": {}},
            "result": {"isError": True, "content": [{"text": "Failed"}]},
            "actor": "agent:bot",
        }
        event = mcp_event(row)
        self.assertEqual(event.outcome, "error")


class OpenAiAdapterTests(unittest.TestCase):
    def test_tool_call_with_string_arguments(self):
        row = {
            "id": "call_12345",
            "type": "function",
            "function": {
                "name": "transfer_funds",
                "arguments": '{"amount": 500, "recipient": "vendor-99"}',
            },
            "actor": "agent:finance",
        }
        event = openai_event(row)
        self.assertIsNotNone(event)
        self.assertEqual(event.actor, "agent:finance")
        self.assertEqual(event.action, "transfer_funds")
        self.assertEqual(event.metadata["amount"], 500)
        self.assertEqual(event.metadata["recipient"], "vendor-99")
        self.assertEqual(event.metadata["tool_call_id"], "call_12345")
        self.assertEqual(event.outcome, "success")

    def test_tool_call_with_dict_arguments(self):
        row = {
            "function": {
                "name": "search_docs",
                "arguments": {"query": "SOC 2"},
            },
            "actor": "agent:assistant",
        }
        event = openai_event(row)
        self.assertEqual(event.action, "search_docs")
        self.assertEqual(event.metadata["query"], "SOC 2")

    def test_chat_completion_tool_call_item(self):
        row = {
            "tool_call_id": "call_abc",
            "name": "execute_code",
            "arguments": {"code": "print('hello')"},
            "output": "hello\n",
        }
        event = openai_event(row, actor_default="agent:coder")
        self.assertEqual(event.actor, "agent:coder")
        self.assertEqual(event.action, "execute_code")
        self.assertEqual(event.metadata["output"], "hello\n")

    def test_error_status(self):
        row = {
            "name": "fetch_url",
            "arguments": {"url": "https://example.invalid"},
            "error": "Connection timed out",
            "actor": "agent:fetcher",
        }
        event = openai_event(row)
        self.assertEqual(event.outcome, "error")
        self.assertEqual(event.metadata["error"], "Connection timed out")


class LangGraphAdapterTests(unittest.TestCase):
    def test_on_tool_end_event(self):
        row = {
            "event": "on_tool_end",
            "name": "sql_query",
            "data": {
                "input": {"sql": "SELECT count(*) FROM users"},
                "output": "42",
            },
            "actor": "agent:sql-agent",
        }
        event = langgraph_event(row)
        self.assertIsNotNone(event)
        self.assertEqual(event.actor, "agent:sql-agent")
        self.assertEqual(event.action, "sql_query")
        self.assertEqual(event.metadata["sql"], "SELECT count(*) FROM users")
        self.assertEqual(event.metadata["output"], "42")
        self.assertEqual(event.outcome, "success")

    def test_tool_message_format(self):
        row = {
            "type": "tool",
            "name": "weather_lookup",
            "content": "{\"temp\": 72, \"condition\": \"sunny\"}",
            "tool_call_id": "call_weather_1",
            "actor": "agent:weather",
        }
        event = langgraph_event(row)
        self.assertEqual(event.action, "weather_lookup")
        self.assertEqual(event.metadata["content"]["temp"], 72)
        self.assertEqual(event.metadata["tool_call_id"], "call_weather_1")

    def test_node_execution_format(self):
        row = {
            "node": "payment_tool",
            "action": "charge_card",
            "input": {"amount": 100},
        }
        event = langgraph_event(row)
        self.assertEqual(event.actor, "payment_tool")
        self.assertEqual(event.action, "charge_card")
        self.assertEqual(event.metadata["amount"], 100)

    def test_error_event(self):
        row = {
            "name": "flaky_tool",
            "input": {},
            "error": "Service unavailable",
            "actor": "agent:test",
        }
        event = langgraph_event(row)
        self.assertEqual(event.outcome, "error")


class CrewAiAdapterTests(unittest.TestCase):
    def test_agent_tool_execution(self):
        row = {
            "agent": "Senior Market Analyst",
            "tool": "stock_ticker_lookup",
            "tool_input": {"symbol": "AAPL"},
            "result": "225.50 USD",
            "thought": "Need latest closing price",
        }
        event = crewai_event(row)
        self.assertIsNotNone(event)
        self.assertEqual(event.actor, "Senior Market Analyst")
        self.assertEqual(event.action, "stock_ticker_lookup")
        self.assertEqual(event.metadata["symbol"], "AAPL")
        self.assertEqual(event.metadata["result"], "225.50 USD")
        self.assertEqual(event.metadata["thought"], "Need latest closing price")
        self.assertEqual(event.outcome, "success")

    def test_action_input_format(self):
        row = {
            "agent_role": "Customer Support Lead",
            "action": "issue_refund",
            "action_input": {"order_id": "ord_882", "amount": 49.99},
        }
        event = crewai_event(row)
        self.assertEqual(event.actor, "Customer Support Lead")
        self.assertEqual(event.action, "issue_refund")
        self.assertEqual(event.metadata["amount"], 49.99)


class AdapterDispatcherTests(unittest.TestCase):
    def test_known_adapters(self):
        self.assertIn("generic", ADAPTERS)
        self.assertIn("mcp", ADAPTERS)
        self.assertIn("openai", ADAPTERS)
        self.assertIn("langgraph", ADAPTERS)
        self.assertIn("crewai", ADAPTERS)

    def test_unknown_format_raises(self):
        with self.assertRaises(ValidationError):
            adapt_event("unknown_sdk", {})

    def test_parse_event_stream(self):
        stream = "\n".join([
            json.dumps({"actor": "a1", "action": "step1"}),
            json.dumps({"actor": "a2", "action": "step2"}),
        ])
        events = parse_event_stream(stream, "generic")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].action, "step1")
        self.assertEqual(events[1].action, "step2")


if __name__ == "__main__":
    unittest.main()
