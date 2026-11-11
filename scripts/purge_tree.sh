#!/usr/bin/env bash
# Remove one ADW worktree (and optionally its local branch) after the run is finished or abandoned.
# Usage: scripts/purge_tree.sh <adw_id> [--delete-branch] [--force]
# Without --force it refuses a worktree with uncommitted or untracked changes and a branch not merged
# into the current HEAD. HEAD, main, master and $TAC_BASE_BRANCH are never deleted.
set -euo pipefail
cd "$(dirname "$0")/.."
usage="usage: purge_tree.sh <adw_id> [--delete-branch] [--force]"
id="${1:?$usage}"
shift
[[ "$id" =~ ^[a-f0-9]{8}$ ]] || { echo "invalid adw_id" >&2; exit 2; }
delete_branch=0 force=0
for arg in "$@"; do
  case "$arg" in
    --delete-branch) delete_branch=1 ;;
    --force) force=1 ;;
    *) echo "$usage" >&2; exit 2 ;;
  esac
done
tree="trees/$id"
if [ ! -e "$tree/.git" ]; then
  [ -e "$tree" ] && { echo "$tree is not a git worktree; inspect and remove it by hand" >&2; exit 1; }
  echo "no worktree at $tree"
  git worktree prune
  exit 0
fi
branch="$(git -C "$tree" symbolic-ref --quiet --short HEAD || true)"
case "$branch" in
  "" | HEAD | main | master | "${TAC_BASE_BRANCH:-main}") protected=1 ;;
  *) protected=0 ;;
esac
if [ "$force" = 0 ]; then
  if [ -n "$(git -C "$tree" status --porcelain)" ]; then
    echo "$tree has uncommitted or untracked changes; commit them or re-run with --force" >&2
    exit 1
  fi
  if [ "$delete_branch" = 1 ] && [ "$protected" = 0 ] && ! git merge-base --is-ancestor "$branch" HEAD; then
    echo "branch $branch is not merged into HEAD; re-run with --force to delete it anyway" >&2
    exit 1
  fi
fi
if [ "$force" = 1 ]; then git worktree remove --force "$tree"; else git worktree remove "$tree"; fi
git worktree prune
echo "removed $tree"
if [ "$delete_branch" = 1 ]; then
  if [ "$protected" = 1 ]; then
    echo "kept branch '${branch:-<detached HEAD>}'" >&2
  else
    git branch -D "$branch"
  fi
fi
