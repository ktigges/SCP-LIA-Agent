"""Azure OpenAI orchestrator (openai Python package, chat-completions tool calling).

Security Copilot's orchestrator runs on Azure OpenAI GPT-4-class models, so this is
the closest SCU-free stand-in for the model behaviour you will see in Security
Copilot. It is still not identical: Security Copilot adds its own orchestration
prompt around the agent Instructions.

Environment:
  AZURE_OPENAI_ENDPOINT     https://<resource>.openai.azure.com
  AZURE_OPENAI_DEPLOYMENT   deployment name (for example gpt-4.1 or gpt-4o)
  AZURE_OPENAI_API_KEY      optional; if unset, an Entra token from `az` is used
  AZURE_OPENAI_API_VERSION  optional; default 2024-10-21
"""
import json
import os
import subprocess

from openai import AzureOpenAI

from .llm_common import extract_json, report_json_prompt, system_prompt, tool_defs

MAX_STEPS = 30


def _az_cognitive_token():
    out = subprocess.run(["az", "account", "get-access-token", "--resource", "https://cognitiveservices.azure.com",
                          "--query", "accessToken", "-o", "tsv"], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise SystemExit(f"Could not get an Azure OpenAI token from az: {out.stderr.strip()}")
    return out.stdout.strip()


class AzureOpenAIAgent:
    name = "azure-openai"

    def __init__(self, contract, now_utc, model=None):
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        self.deployment = model or os.environ.get("AZURE_OPENAI_DEPLOYMENT")
        if not endpoint or not self.deployment:
            raise SystemExit("Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT (or pass --model).")
        kw = dict(azure_endpoint=endpoint, api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"))
        if os.environ.get("AZURE_OPENAI_API_KEY"):
            kw["api_key"] = os.environ["AZURE_OPENAI_API_KEY"]
        else:
            kw["azure_ad_token"] = _az_cognitive_token()
        self.client = AzureOpenAI(**kw)
        self.model = self.deployment
        self.tools = [{"type": "function", "function": {"name": n, "description": d, "parameters": s}}
                      for n, d, s in tool_defs(contract)]
        self.messages = [{"role": "system", "content": system_prompt(contract, now_utc)}]
        self.usage = {"input_tokens": 0, "output_tokens": 0}

    def run_turn(self, session, user_text):
        session.begin_turn(user_text)
        self.messages.append({"role": "user", "content": user_text})
        reply = ""
        for _ in range(MAX_STEPS):
            resp = self.client.chat.completions.create(model=self.deployment, messages=self.messages,
                                                       tools=self.tools, temperature=0)
            if resp.usage:
                self.usage["input_tokens"] += resp.usage.prompt_tokens
                self.usage["output_tokens"] += resp.usage.completion_tokens
            msg = resp.choices[0].message
            self.messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                reply = msg.content or ""
                break
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {"_unparseable_arguments": tc.function.arguments}
                rows, err = session.call(tc.function.name, args)
                self.messages.append({"role": "tool", "tool_call_id": tc.id,
                                      "content": session.render_result(rows, err)})
        else:
            reply = "[harness: step limit reached]"
        session.end_turn(reply)
        return reply

    def report_to_json(self, report_md):
        resp = self.client.chat.completions.create(
            model=self.deployment, temperature=0, response_format={"type": "json_object"},
            messages=[{"role": "user", "content": report_json_prompt(report_md)}])
        return extract_json(resp.choices[0].message.content)
