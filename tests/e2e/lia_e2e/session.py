"""Records every tool call an orchestrator makes, for grading."""
import json
import time

from .mock_backend import ToolError


class ToolSession:
    def __init__(self, backend, approved_tools):
        self.backend = backend
        self.approved = set(approved_tools)
        self.turns = []

    def begin_turn(self, user_text):
        self.turns.append({"user": user_text, "calls": [], "reply": ""})

    def end_turn(self, reply):
        self.turns[-1]["reply"] = reply

    def call(self, tool, args):
        """Returns (rows, None) or (None, ToolError). Never raises for tool errors."""
        rec = {"tool": tool, "args": dict(args), "approved": tool in self.approved}
        t0 = time.time()
        if tool not in self.approved:
            err = ToolError("QueryFailed", f"Tool '{tool}' is not allowed by the plugin AllowedTools list")
            rec.update(ok=False, error={"kind": err.kind, "message": err.message})
            self.turns[-1]["calls"].append(rec)
            return None, err
        try:
            rows = self.backend.call(tool, args)
            rec.update(ok=True, rows=rows)
            result = (rows, None)
        except ToolError as e:
            rec.update(ok=False, error={"kind": e.kind, "message": e.message})
            result = (None, e)
        rec["seconds"] = round(time.time() - t0, 3)
        self.turns[-1]["calls"].append(rec)
        return result

    @staticmethod
    def render_result(rows, err):
        """What an LLM orchestrator sees as the tool result."""
        if err is not None:
            return f"Tool call failed. Error: {err.message}"
        return json.dumps({"rowCount": len(rows), "rows": rows}, default=str)

    def transcript(self):
        return {"turns": self.turns}
