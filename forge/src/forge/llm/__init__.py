"""Designers: the deterministic default and an optional Gemini assistant."""

from . import deterministic, gemini

DESIGNERS = ("deterministic", "gemini")

__all__ = ["deterministic", "gemini", "DESIGNERS"]
