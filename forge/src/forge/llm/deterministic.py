"""The default designer: pure graph inference, no model, no network.

Every parameter it proposes is derived from the intent graph by a fixed rule.
Same intent in, same parameters out, forever -- which is what makes the
``strict`` reproducibility check and the signed manifest worth anything.

This is the designer that runs unless you explicitly ask for Gemini, and it is
the one that should run in CI. A build that needs a network call to reproduce
is not reproducible.
"""

from __future__ import annotations

from typing import Any

from ..intent import Intent

NAME = "deterministic"


def propose(intent: Intent) -> dict[str, dict[str, Any]]:
    """Infer per-node parameters from graph topology alone."""
    proposals: dict[str, dict[str, Any]] = {}

    for node in intent.nodes:
        inbound = intent.inbound(node.id)
        outbound = intent.outbound(node.id)
        params: dict[str, Any] = {}

        if node.kind == "endpoint":
            params["route"] = node.id.replace("_", "-")
            # A node with inbound data flow accepts writes; a pure source reads.
            params["methods"] = ["post"] if inbound else ["get"]

        # Terminal nodes are where data comes to rest.
        if not outbound and inbound:
            params["terminal"] = True
        if not inbound and outbound:
            params["origin"] = True

        fan_in = len(inbound)
        fan_out = len(outbound)
        if fan_in > 1:
            params["multiplexed"] = True
        if fan_out > 1:
            params["broadcasts"] = True

        if params:
            proposals[node.id] = params

    return proposals


__all__ = ["NAME", "propose"]
