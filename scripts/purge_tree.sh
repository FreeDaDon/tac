#!/usr/bin/env bash
# Remove one ADW worktree (and its local branch) after the run is finished or abandoned.
# Usage: scripts/purge_tree.sh <adw_id> [--delete-branch]
set -euo pipefail
cd "$(dirname "$0")/.."
id="${1:?usage: purge_tree.sh <adw_id> [--delete-branch]}"
[[ "$id" =~ ^[a-f0-9]{8}$ ]] || { echo "invalid adw_id" >&2; exit 2; }
branch="$(git -C "trees/$id" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
git worktree remove --force "trees/$id" 2>/dev/null || true
git worktree prune
if [ "${2:-}" = "--delete-branch" ] && [ -n "$branch" ] && [ "$branch" != "main" ]; then
  git branch -D "$branch"
fi
echo "removed trees/$id"
