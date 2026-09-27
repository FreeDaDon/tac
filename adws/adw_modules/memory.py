"""Lessons memory: one durable lesson per file in agent/lessons/, retrieved by tag/keyword overlap.

Deliberately simple (files + frontmatter, no vector DB): inspectable, diffable, and cheap.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from .security import sanitize_untrusted
from .utils import agent_dir

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,60}$")
_WORD_RE = re.compile(r"[a-z0-9_]{3,}")


class Lesson(BaseModel):
    slug: str
    title: str
    tags: list[str] = Field(default_factory=list)
    lesson: str
    why: str = ""
    how_to_apply: str = ""
    source_adw: str = ""


def lessons_dir() -> Path:
    return agent_dir() / "lessons"


def _render(lesson: Lesson) -> str:
    tags = ", ".join(sorted({t.lower() for t in lesson.tags}))
    return (
        f"---\nname: {lesson.slug}\ndescription: {lesson.title}\ntags: [{tags}]\n"
        f"source_adw: {lesson.source_adw}\n---\n\n{lesson.lesson}\n\n"
        f"**Why:** {lesson.why}\n\n**How to apply:** {lesson.how_to_apply}\n"
    )


def _parse(path: Path) -> Lesson | None:
    text = path.read_text()
    m = re.match(r"---\n(.*?)\n---\n(.*)", text, re.DOTALL)
    if not m:
        return None
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    body = m.group(2).strip()
    tags = [t.strip() for t in meta.get("tags", "").strip("[]").split(",") if t.strip()]
    why = re.search(r"\*\*Why:\*\*\s*(.*?)(?:\n\n|$)", body, re.DOTALL)
    how = re.search(r"\*\*How to apply:\*\*\s*(.*)$", body, re.DOTALL)
    lesson_text = body.split("**Why:**")[0].strip()
    return Lesson(
        slug=meta.get("name", path.stem), title=meta.get("description", ""), tags=tags, lesson=lesson_text,
        why=why.group(1).strip() if why else "", how_to_apply=how.group(1).strip() if how else "",
        source_adw=meta.get("source_adw", ""),
    )


def write_lesson(lesson: Lesson) -> Path:
    """Create or update (never duplicate) a lesson file; refresh the index."""
    if not SLUG_RE.match(lesson.slug):
        raise ValueError(f"invalid lesson slug {lesson.slug!r}")
    clean = lesson.model_copy(update={
        "title": sanitize_untrusted(lesson.title, 200).replace("\n", " "),
        "lesson": sanitize_untrusted(lesson.lesson, 2000),
        "why": sanitize_untrusted(lesson.why, 1000),
        "how_to_apply": sanitize_untrusted(lesson.how_to_apply, 1000),
        "tags": [re.sub(r"[^a-z0-9-]", "", t.lower())[:30] for t in lesson.tags][:8],
    })
    d = lessons_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{clean.slug}.md"
    path.write_text(_render(clean))
    rebuild_index()
    return path


def load_lessons() -> list[Lesson]:
    d = lessons_dir()
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.md")):
        if p.name == "INDEX.md":
            continue
        parsed = _parse(p)
        if parsed:
            out.append(parsed)
    return out


def rebuild_index() -> None:
    lines = ["# Lessons index", "", "One lesson per file. `/prime` loads the relevant ones.", ""]
    lines += [f"- [{lsn.title}]({lsn.slug}.md) — tags: {', '.join(lsn.tags)}" for lsn in load_lessons()]
    (lessons_dir() / "INDEX.md").write_text("\n".join(lines) + "\n")


def relevant(query: str, tags: list[str] | None = None, k: int = 5) -> list[Lesson]:
    words = set(_WORD_RE.findall(query.lower()))
    tagset = {t.lower() for t in tags or []}
    scored = []
    for lsn in load_lessons():
        text_words = set(_WORD_RE.findall(f"{lsn.title} {lsn.lesson}".lower()))
        score = 3 * len(tagset & set(lsn.tags)) + 2 * len(words & set(lsn.tags)) + len(words & text_words)
        if score:
            scored.append((score, lsn.slug, lsn))
    return [lsn for _, _, lsn in sorted(scored, key=lambda s: (-s[0], s[1]))[:k]]


def format_for_prompt(lessons: list[Lesson]) -> str:
    if not lessons:
        return ""
    parts = ["## Lessons from previous runs (apply where relevant)"]
    for lsn in lessons:
        parts.append(f"- **{lsn.title}**: {lsn.lesson} (How to apply: {lsn.how_to_apply})")
    return "\n".join(parts)
