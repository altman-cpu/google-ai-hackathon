"""Generator package.

Importing this package registers every built-in generator. The imports look
unused -- they are not; each module calls ``@register`` at import time.
"""

from . import drf_endpoint as _drf_endpoint  # noqa: F401
from . import python_module as _python_module  # noqa: F401
from .base import Generator, available, get, register

__all__ = ["Generator", "available", "get", "register"]
