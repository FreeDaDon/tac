#!/usr/bin/env -S uv run
"""Zero-Touch Engineering: full SDLC, then ship (auto-merge) only if every ship lock is open.

See adw_ship_iso.py for the locks. With TAC_ZTE_ENABLED unset this runs the whole pipeline and
stops at a reviewed PR, printing exactly which locks stayed closed.

Usage: uv run adws/adw_sdlc_zte_iso.py --issue 42 [--model-set heavy]
"""

from __future__ import annotations

from adws import adw_ship_iso
from adws.adw_modules.cli import main_wrapper
from adws.adw_sdlc_iso import build_parser, run_pipeline


def main() -> None:
    p = build_parser(__doc__)
    a = p.parse_args()
    if a.skip_e2e:
        p.error("--skip-e2e is not allowed for Zero-Touch runs")
    if not (a.issue or a.issue_file or (a.adw_id and a.resume)):
        p.error("provide --issue, --issue-file, or --adw-id with --resume")

    def entry() -> bool:
        ok, adw_id = run_pipeline(a)
        return ok and adw_ship_iso.run(adw_id)

    main_wrapper(entry, lambda: a.adw_id)


if __name__ == "__main__":
    main()
