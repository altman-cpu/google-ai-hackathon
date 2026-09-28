"""Generator: a typed service module for a non-endpoint node.

Emits a module containing a frozen dataclass for every payload type that flows
into or out of the node, plus a handler class whose method signatures are
derived from the edges. Constraints in the intent become runtime guards in the
generated code -- ``max_bytes`` becomes a size check, ``pii`` becomes a
redacting ``__repr__``, ``idempotent`` becomes a dedupe key parameter.
"""

from __future__ import annotations

from ..design import Plan, Step
from ..transform import Artifact
from .base import docstring, header, pascal, register, render, snake


@register("python_module")
def generate(step: Step, plan: Plan) -> list[Artifact]:
    context = step.context()
    node = step.node
    class_name = pascal(node.id)
    payload_types = sorted(set(context["carries_in"]) | set(context["carries_out"]))


    lines = header(step, plan)
    lines += ["from dataclasses import dataclass", "from typing import Any, Protocol", ""]

    if context["max_bytes"]:
        lines += [
            f"# Tightest max_bytes across inbound edges, taken from the intent.",
            f"MAX_PAYLOAD_BYTES = {context['max_bytes']}",
            "",
        ]
    if context["rate_limit"]:
        lines += [f"RATE_LIMIT_PER_MINUTE = {context['rate_limit']}", ""]

    lines += ["", f"class {class_name}Error(Exception):"]
    lines += docstring([f"Raised when {node.id} rejects an operation."])
    lines += [""]

    for payload in payload_types:
        lines += _payload_class(payload, context["handles_pii"])

    lines += _handler_protocol(class_name, node.id, step, context)
    lines += _service_class(class_name, node.id, step, context)

    module_path = f"{plan.intent.name.replace('-', '_')}/{snake(node.id)}.py"
    return [
        Artifact(
            path=module_path,
            content=render(lines),
            media_type="text/x-python",
        )
    ]


def _payload_class(payload: str, pii: bool) -> list[str]:
    lines = ["", "@dataclass(frozen=True)", f"class {payload}:"]
    body = [f"Payload carried across an intent edge."]
    if pii:
        body += ["", "Marked pii in the intent: __repr__ is redacted so the value", "cannot leak into logs or tracebacks."]
    lines += docstring(body)
    lines += ["", "    payload: dict[str, Any]", ""]
    if pii:
        lines += [
            "    def __repr__(self) -> str:",
            f'        return f"{payload}(redacted, {{len(self.payload)}} fields)"',
            "",
        ]
    return lines


def _handler_protocol(class_name: str, node_id: str, step: Step, context: dict) -> list[str]:
    lines = ["", f"class {class_name}Handler(Protocol):"]
    lines += docstring(
        [
            f"Behaviour {node_id} requires from its implementation.",
            "",
            "One method per distinct inbound payload type. Implement this",
            "protocol; forge regenerates the contract, never your logic.",
        ]
    )
    lines += [""]
    if not context["accepts"]:
        lines += ["    ...", ""]
        return lines
    for payload in context["accepts"]:
        arg = snake(payload)
        suffix = ", dedupe_key: str" if context["idempotent"] else ""
        lines += [
            f"    def handle_{arg}(self, message: {payload}{suffix}) -> Any: ...",
            "",
        ]
    return lines


def _service_class(class_name: str, node_id: str, step: Step, context: dict) -> list[str]:
    lines = ["", f"class {class_name}:"]
    doc = [f"Intent-derived entry point for the {node_id} node."]
    if context["sources"]:
        doc += ["", "Receives from: " + ", ".join(context["sources"])]
    if context["targets"]:
        doc += ["Sends to: " + ", ".join(context["targets"])]
    if context["auth"] != "none":
        doc += ["", f"Every inbound edge requires auth={context['auth']}."]
    lines += docstring(doc)
    lines += [
        "",
        f"    def __init__(self, handler: {class_name}Handler) -> None:",
        "        self.handler = handler",
    ]
    if context["idempotent"]:
        lines += ["        self._seen: dict[str, Any] = {}"]
    lines += [""]

    for payload in context["accepts"]:
        arg = snake(payload)
        params = f"self, message: {payload}"
        if context["idempotent"]:
            params += ", dedupe_key: str"
        lines += [f"    def accept_{arg}({params}) -> Any:"]
        lines += docstring([f"Validate and dispatch a {payload}."], indent="        ")

        if context["auth"] != "none":
            lines += [
                f"        # The intent requires auth={context['auth']} on this flow.",
                "        # Enforcement belongs at the transport boundary, not here:",
                "        # this class is called after the caller is already authenticated.",
            ]
        if context["max_bytes"]:
            lines += [
                "        size = len(repr(message.payload).encode('utf-8'))",
                "        if size > MAX_PAYLOAD_BYTES:",
                f"            raise {pascal(node_id)}Error(",
                f'                f"{payload} is {{size}} bytes, exceeding the '
                f'{{MAX_PAYLOAD_BYTES}} byte limit declared in the intent"',
                "            )",
            ]
        if context["idempotent"]:
            lines += [
                "        if dedupe_key in self._seen:",
                "            # Edge is idempotent: replay returns the first result.",
                "            return self._seen[dedupe_key]",
                f"        result = self.handler.handle_{arg}(message, dedupe_key)",
                "        self._seen[dedupe_key] = result",
                "        return result",
            ]
        else:
            lines += [f"        return self.handler.handle_{arg}(message)"]
        lines += [""]

    if not context["accepts"]:
        lines += ["    # No governing edges in the intent: nothing to accept.", "    pass", ""]
    return lines
