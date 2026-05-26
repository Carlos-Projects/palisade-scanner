"""Adapter: palisade-scanner -> mcp-taxonomy."""

from mcp_taxonomy import palisade_finding_to_taxonomy as _normalize


def normalize_finding(finding) -> dict:
    """Convert a palisade Finding (dict or object) to a normalized taxonomy dict."""
    event = _normalize(finding)
    return {
        "source": event.source,
        "attack_category": event.attack_category.value,
        "severity": event.severity.value,
        "confidence": event.confidence.value,
        "title": event.title,
        "description": event.description,
        "recommendation": event.recommendation,
        "target": event.target,
        "snippet": event.snippet[:200],
        "risk_score": event.risk_score,
    }
