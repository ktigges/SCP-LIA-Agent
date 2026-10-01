"""Claude orchestrator (Anthropic Python SDK, manual tool-use loop).

A manual loop (rather than the SDK tool runner) keeps every tool call inside the
harness's ToolSession, so faults are injected and each call is recorded exactly
as it happened. Credentials come from the standard SDK chain
(ANTHROPIC_API_KEY, or an `ant auth login` profile).
"""
import anthropic

from .llm_common import extract_json, report_json_prompt, system_prompt, tool_defs

DEFAULT_MODEL = "claude-opus-5"
MAX_STEPS = 30


class ClaudeAgent:
    name = "claude"

    def __init__(self, contract, now_utc, model=None):
        self.client = anthropic.Anthropic()
        self.model = model or DEFAULT_MODEL
        self.system = system_prompt(contract, now_utc)
        self.tools = [{"name": n, "description": d, "input_schema": s} for n, d, s in tool_defs(contract)]
        self.messages = []
        self.usage = {"input_tokens": 0, "output_tokens": 0}

    def _create(self, **kw):
        # Server-side refusal fallback (beta) so a safety-classifier refusal on
        # security content is retried on a fallback model instead of failing the run.
        return self.client.beta.messages.create(
            model=self.model, max_tokens=16000, thinking={"type": "adaptive"},
            betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kw)

    def run_turn(self, session, user_text):
        session.begin_turn(user_text)
        self.messages.append({"role": "user", "content": user_text})
        reply = ""
        for _ in range(MAX_STEPS):
            resp = self._create(system=self.system, tools=self.tools, messages=self.messages)
            self.usage["input_tokens"] += resp.usage.input_tokens
            self.usage["output_tokens"] += resp.usage.output_tokens
            if resp.stop_reason == "refusal":
                reply = f"[model refusal: {getattr(resp, 'stop_details', None)}]"
                break
            self.messages.append({"role": "assistant", "content": resp.content})
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if resp.stop_reason != "tool_use" or not tool_uses:
                reply = "\n".join(b.text for b in resp.content if b.type == "text")
                break
            results = []
            for b in tool_uses:
                rows, err = session.call(b.name, b.input)
                results.append({"type": "tool_result", "tool_use_id": b.id,
                                "content": session.render_result(rows, err), "is_error": err is not None})
            self.messages.append({"role": "user", "content": results})
        else:
            reply = "[harness: step limit reached]"
        session.end_turn(reply)
        return reply

    def report_to_json(self, report_md):
        resp = self.client.messages.create(model=self.model, max_tokens=16000,
                                           messages=[{"role": "user", "content": report_json_prompt(report_md)}])
        return extract_json("".join(b.text for b in resp.content if b.type == "text"))
