"""Formats a table; no network, no filesystem outside its arguments."""


def render(rows: list[list[str]]) -> str:
    return "\n".join(" | ".join(r) for r in rows)
