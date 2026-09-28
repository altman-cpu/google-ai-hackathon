"""Intent -> build plan.

The designer resolves an intent graph into a deterministic, topologically
ordered sequence of build steps. Producers are built before consumers, so a
generator can always see the resolved shape of everything upstream of it.

Determinism detail: Kahn's algorithm is only deterministic if the ready-set is
drained in a fixed order. A plain ``set`` would make build order depend on
Python's hash seed. We use a heap keyed on node id, so the plan -- and every
digest derived from it -- is stable across processes and machines.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Any

from .errors import DesignError
from .hashing import digest_object, hex_be
from .intent import Edge, Intent, Node

SCHEMA_PLAN = "forge.plan/v1"


@dataclass(frozen=True)
class Step:
    """One node, resolved and ready to hand to a generator."""

    node: Node
    inbound: tuple[Edge, ...]
    outbound: tuple[Edge, ...]
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.node.id

    @property
    def generator(self) -> str:
        return self.node.generator

    def document(self) -> dict[str, Any]:
        return {
            "generator": self.generator,
            "inbound": [edge.document() for edge in self.inbound],
            "node": self.node.document(),
            "outbound": [edge.document() for edge in self.outbound],
            "params": self.params,
        }

    def context(self) -> dict[str, Any]:
        """Flow summary handed to generators as template context."""
        return {
            "accepts": self.accepts,
            "auth": self.effective_auth,
            "carries_in": sorted({edge.carries for edge in self.inbound}),
            "carries_out": sorted({edge.carries for edge in self.outbound}),
            "handles_pii": self.handles_pii,
            "idempotent": self.is_idempotent,
            "is_origin": self.is_origin,
            "max_bytes": self.max_bytes,
            "rate_limit": self.rate_limit,
            "sources": sorted({edge.source for edge in self.inbound}),
            "targets": sorted({edge.target for edge in self.outbound}),
        }

    @property
    def constraint_edges(self) -> tuple[Edge, ...]:
        """The edges that govern this node's own enforcement.

        Normally a node's obligations come from its *inbound* edges: those
        describe the calls it must accept and therefore police.

        A node with no inbound edges is an **origin** -- it is entered from
        outside the graph, where no edge exists to describe the call. Resolving
        its constraints to "none" would leave the front door of the system
        completely unguarded, which is exactly the node that most needs
        guarding. So an origin inherits from its *outbound* edges instead: if
        the data leaving here is authenticated, size-capped, and idempotent,
        then the data arriving from outside is at least as sensitive and gets
        the same treatment.
        """
        return self.inbound if self.inbound else self.outbound

    @property
    def is_origin(self) -> bool:
        """True when this node is entered from outside the intent graph."""
        return not self.inbound

    @property
    def accepts(self) -> list[str]:
        """Payload types this node must be able to receive.

        For an ordinary node these are the inbound types. For an origin the
        caller is outside the graph, so the best available description of what
        it receives is what it emits.
        """
        return sorted({edge.carries for edge in self.constraint_edges})

    @property
    def effective_auth(self) -> str:
        """Strongest auth demanded by the governing edges.

        An explicit ``params.auth`` on the node overrides the derivation.
        """
        order = {"none": 0, "service": 1, "required": 2}

        declared = self.params.get("auth")
        if isinstance(declared, str) and declared in order:
            return declared

        best = "none"
        for edge in self.constraint_edges:
            mode = str(edge.constraints.get("auth", "none"))
            if order.get(mode, 0) > order[best]:
                best = mode
        return best

    @property
    def handles_pii(self) -> bool:
        return any(edge.constraints.get("pii", False) for edge in self.inbound + self.outbound)

    @property
    def is_idempotent(self) -> bool:
        """Only idempotent if *every* governing edge says so.

        Unanimity, not majority: one non-idempotent caller is enough to make
        replay unsafe, so a single dissenting edge disables the guarantee.
        """
        edges = self.constraint_edges
        if not edges:
            return False
        return all(edge.constraints.get("idempotent", False) for edge in edges)

    @property
    def max_bytes(self) -> int:
        """Tightest payload limit across governing edges; 0 means unconstrained."""
        limits = [
            int(edge.constraints["max_bytes"])
            for edge in self.constraint_edges
            if "max_bytes" in edge.constraints
        ]
        return min(limits) if limits else 0

    @property
    def rate_limit(self) -> int:
        """Tightest rate limit across governing edges; 0 means unlimited."""
        limits = [
            int(edge.constraints["rate_limit"])
            for edge in self.constraint_edges
            if edge.constraints.get("rate_limit", 0) > 0
        ]
        return min(limits) if limits else 0


@dataclass(frozen=True)
class Plan:
    """A fully resolved, ordered build plan."""

    intent: Intent
    steps: tuple[Step, ...]
    designer: str = "deterministic"
    warnings: tuple[str, ...] = ()

    def document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PLAN,
            "designer": self.designer,
            "intent_digest": self.intent.digest_hex,
            "intent_name": self.intent.name,
            "order": [step.id for step in self.steps],
            "steps": [step.document() for step in self.steps],
        }

    @property
    def digest(self) -> bytes:
        return digest_object(self.document())

    @property
    def digest_hex(self) -> str:
        return hex_be(self.digest)

    def step(self, node_id: str) -> Step:
        for step in self.steps:
            if step.id == node_id:
                return step
        raise DesignError(f"plan has no step for node {node_id!r}")


def resolve(intent: Intent, *, designer: str = "deterministic",
            overrides: dict[str, dict[str, Any]] | None = None) -> Plan:
    """Resolve ``intent`` into an ordered :class:`Plan`.

    ``overrides`` maps node id -> extra params, used by the LLM designer to
    contribute suggestions. Overrides can only *add* parameters to nodes that
    already exist in the intent; they can never introduce a node.
    """
    order = topological_order(intent)
    overrides = overrides or {}

    unknown = sorted(set(overrides) - {node.id for node in intent.nodes})
    if unknown:
        raise DesignError(
            "designer proposed parameters for nodes that the intent never declared: "
            + ", ".join(unknown)
            + "\n  The intent graph is authoritative; a designer may refine it, not extend it."
        )

    steps: list[Step] = []
    for node_id in order:
        node = intent.node(node_id)
        params = dict(node.params)
        for key, value in sorted(overrides.get(node_id, {}).items()):
            # Author-declared params always win over designer suggestions.
            params.setdefault(key, value)
        steps.append(
            Step(
                node=node,
                inbound=tuple(intent.inbound(node_id)),
                outbound=tuple(intent.outbound(node_id)),
                params=params,
            )
        )

    return Plan(intent=intent, steps=tuple(steps), designer=designer)


def topological_order(intent: Intent) -> list[str]:
    """Kahn's algorithm with a min-heap tie-break for stable ordering."""
    indegree: dict[str, int] = {node.id: 0 for node in intent.nodes}
    adjacency: dict[str, list[str]] = {node.id: [] for node in intent.nodes}

    for edge in intent.edges:
        adjacency[edge.source].append(edge.target)
        indegree[edge.target] += 1
    for key in adjacency:
        adjacency[key].sort()

    ready = [node_id for node_id, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)

    order: list[str] = []
    while ready:
        node_id = heapq.heappop(ready)
        order.append(node_id)
        for neighbour in adjacency[node_id]:
            indegree[neighbour] -= 1
            if indegree[neighbour] == 0:
                heapq.heappush(ready, neighbour)

    if len(order) != len(intent.nodes):
        stuck = sorted(set(indegree) - set(order))
        raise DesignError(
            "intent network could not be ordered; these nodes are in or behind a cycle: "
            + ", ".join(stuck)
        )
    return order


__all__ = ["SCHEMA_PLAN", "Step", "Plan", "resolve", "topological_order"]
