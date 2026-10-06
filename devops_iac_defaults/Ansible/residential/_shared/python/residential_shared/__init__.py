"""Opt-in shared helpers for residential device APIs. Existing apps are untouched."""

from .helpers import health_payload, require_api_key_header

__all__ = ["health_payload", "require_api_key_header"]
