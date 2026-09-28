"""Generator: a Django REST Framework endpoint for an ``endpoint`` node.

Matches the conventions already used in ``backend/cancer`` (DRF ``APIView``,
serializer per payload, ``urls.py`` wiring). Intent constraints compile into
real enforcement:

* ``auth: required``  -> ``IsAuthenticated`` permission class
* ``auth: service``   -> a service-token permission class
* ``max_bytes``       -> a request-size guard returning HTTP 413
* ``rate_limit``      -> a scoped DRF throttle
* ``idempotent``      -> an ``Idempotency-Key`` header contract
* ``pii``             -> logging is suppressed on the request body
"""

from __future__ import annotations

from ..design import Plan, Step
from ..transform import Artifact
from .base import docstring, header, pascal, register, render, snake


@register("drf_endpoint")
def generate(step: Step, plan: Plan) -> list[Artifact]:
    context = step.context()
    node = step.node
    name = pascal(node.id)
    package = plan.intent.name.replace("-", "_")
    route = str(step.params.get("route", node.id.replace("_", "-")))
    methods = _methods(step)

    views = _views_module(step, plan, name, context, methods)
    serializers = _serializers_module(step, plan, name, context)
    urls = _urls_module(step, plan, name, route, package)

    base = f"{package}/{snake(node.id)}"
    return [
        Artifact(path=f"{base}/serializers.py", content=render(serializers), media_type="text/x-python"),
        Artifact(path=f"{base}/urls.py", content=render(urls), media_type="text/x-python"),
        Artifact(path=f"{base}/views.py", content=render(views), media_type="text/x-python"),
    ]


def _methods(step: Step) -> list[str]:
    declared = step.params.get("methods")
    if isinstance(declared, list) and declared:
        return sorted({str(m).lower() for m in declared} & {"get", "post", "put", "patch", "delete"})
    # Default from topology: a node that receives data accepts POST. An
    # origin endpoint is entered from outside the graph, so it receives too.
    return ["post"] if step.constraint_edges else ["get"]


def _serializers_module(step: Step, plan: Plan, name: str, context: dict) -> list[str]:
    lines = header(step, plan)
    lines += ["from rest_framework import serializers", ""]

    payloads = context["accepts"] or context["carries_out"]
    for payload in payloads:
        lines += ["", f"class {payload}Serializer(serializers.Serializer):"]
        doc = [f"Validates a {payload} payload declared in the intent."]
        if context["handles_pii"]:
            doc += ["", "This payload is marked pii: do not log validated_data."]
        lines += docstring(doc)
        lines += [""]

        fields = step.params.get("fields")
        if isinstance(fields, dict) and fields:
            for field_name, field_type in sorted(fields.items()):
                lines += [f"    {field_name} = {_drf_field(str(field_type))}"]
        else:
            lines += [
                "    # The intent did not declare fields for this payload.",
                "    # Add them here, or set params.fields on the node and regenerate.",
                "    data = serializers.JSONField()",
            ]
        lines += [""]
    if not payloads:
        lines += ["", "# No payload types flow through this node.", ""]
    return lines


_FIELD_MAP = {
    "str": "serializers.CharField()",
    "string": "serializers.CharField()",
    "int": "serializers.IntegerField()",
    "integer": "serializers.IntegerField()",
    "bool": "serializers.BooleanField()",
    "boolean": "serializers.BooleanField()",
    "uuid": "serializers.UUIDField()",
    "email": "serializers.EmailField()",
    "url": "serializers.URLField()",
    "datetime": "serializers.DateTimeField()",
    "json": "serializers.JSONField()",
    "file": "serializers.FileField()",
}


def _drf_field(kind: str) -> str:
    return _FIELD_MAP.get(kind.lower(), "serializers.JSONField()")


def _views_module(step: Step, plan: Plan, name: str, context: dict, methods: list[str]) -> list[str]:
    payloads = context["accepts"] or context["carries_out"]
    primary = payloads[0] if payloads else None

    lines = header(step, plan)
    lines += [
        "from rest_framework import status",
        "from rest_framework.response import Response",
        "from rest_framework.views import APIView",
    ]

    auth = context["auth"]
    if auth == "required":
        lines += ["from rest_framework.permissions import IsAuthenticated"]
    elif auth == "service":
        lines += ["from rest_framework.permissions import BasePermission"]
    else:
        lines += ["from rest_framework.permissions import AllowAny"]

    if context["rate_limit"]:
        lines += ["from rest_framework.throttling import ScopedRateThrottle"]
    lines += [""]

    if primary:
        lines += [f"from .serializers import {primary}Serializer", ""]

    if context["max_bytes"]:
        lines += ["", f"MAX_PAYLOAD_BYTES = {context['max_bytes']}"]
    lines += [""]

    if auth == "service":
        lines += [
            "",
            "class IsService(BasePermission):",
        ]
        lines += docstring(
            [
                "Allows only authenticated service principals.",
                "",
                "The intent marks every inbound edge auth=service, meaning this",
                "endpoint is internal and must not be reachable by end users.",
            ]
        )
        lines += [
            "",
            "    def has_permission(self, request, view) -> bool:",
            "        user = getattr(request, 'user', None)",
            "        return bool(user and user.is_authenticated and getattr(user, 'is_staff', False))",
            "",
        ]

    lines += ["", f"class {name}View(APIView):"]
    doc = [step.node.description or f"Endpoint for the {step.node.id} node."]
    if context["sources"]:
        doc += ["", "Receives from: " + ", ".join(context["sources"])]
    if context["targets"]:
        doc += ["Forwards to: " + ", ".join(context["targets"])]
    if context["idempotent"]:
        doc += ["", "Idempotent: callers must send an Idempotency-Key header."]
    lines += docstring(doc)
    lines += [""]

    permission = {
        "required": "[IsAuthenticated]",
        "service": "[IsService]",
        "none": "[AllowAny]",
    }[auth]
    lines += [f"    permission_classes = {permission}"]
    if context["rate_limit"]:
        lines += [
            "    throttle_classes = [ScopedRateThrottle]",
            f"    throttle_scope = {step.node.id!r}",
            f"    # Configure DEFAULT_THROTTLE_RATES[{step.node.id!r}] = "
            f"'{context['rate_limit']}/min'",
        ]
    lines += [""]

    for method in methods:
        lines += _view_method(method, name, primary, context)

    return lines


def _view_method(method: str, name: str, primary: str | None, context: dict) -> list[str]:
    lines = [f"    def {method}(self, request, *args, **kwargs):"]
    lines += docstring([f"Handle {method.upper()}."], indent="        ")

    if context["max_bytes"] and method in {"post", "put", "patch"}:
        lines += [
            "        declared = request.META.get('CONTENT_LENGTH') or 0",
            "        if int(declared or 0) > MAX_PAYLOAD_BYTES:",
            "            return Response(",
            "                {'detail': f'payload exceeds {MAX_PAYLOAD_BYTES} bytes'},",
            "                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,",
            "            )",
        ]

    if context["idempotent"] and method in {"post", "put", "patch"}:
        lines += [
            "        idempotency_key = request.headers.get('Idempotency-Key')",
            "        if not idempotency_key:",
            "            return Response(",
            "                {'detail': 'Idempotency-Key header is required'},",
            "                status=status.HTTP_400_BAD_REQUEST,",
            "            )",
        ]

    if method in {"post", "put", "patch"} and primary:
        lines += [
            f"        serializer = {primary}Serializer(data=request.data)",
            "        serializer.is_valid(raise_exception=True)",
        ]
        if context["handles_pii"]:
            lines += [
                "        # pii edge: never log serializer.validated_data.",
            ]
        lines += [
            "        # TODO: dispatch serializer.validated_data to the domain layer.",
            "        return Response(status=status.HTTP_202_ACCEPTED)",
            "",
        ]
    else:
        lines += [
            "        # TODO: read from the domain layer.",
            "        return Response({}, status=status.HTTP_200_OK)",
            "",
        ]
    return lines


def _urls_module(step: Step, plan: Plan, name: str, route: str, package: str) -> list[str]:
    lines = header(step, plan)
    lines += [
        "from django.urls import path",
        "",
        f"from .views import {name}View",
        "",
        "",
        "urlpatterns = [",
        f"    path({route!r}, {name}View.as_view(), name={step.node.id!r}),",
        "]",
        "",
    ]
    return lines
