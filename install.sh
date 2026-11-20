#!/usr/bin/env bash
# Link the skills into Claude Code and/or Codex so `git pull` in this repo updates them.
#   ./install.sh                 # every skill, both tools
#   ./install.sh claude          # ~/.claude/skills only
#   ./install.sh codex           # ${CODEX_HOME:-~/.codex}/skills only
#   ./install.sh all nginx2root-java4shell   # only the named skills
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)/skills"
target=${1:-all}
shift || true
skills=("$@")
if [ ${#skills[@]} -eq 0 ]; then
  for d in "$root"/*/; do skills+=("$(basename "$d")"); done
fi

link() {
  local dir=$1 s dst
  mkdir -p "$dir"
  for s in "${skills[@]}"; do
    [ -f "$root/$s/SKILL.md" ] || { echo "no such skill: $s" >&2; return 1; }
    dst="$dir/$s"
    if [ -e "$dst" ] && [ ! -L "$dst" ]; then
      echo "$dst exists and is not a symlink; remove it first." >&2
      return 1
    fi
    ln -sfn "$root/$s" "$dst"
    echo "Linked $dst -> $root/$s"
  done
}

case $target in
  claude) link "$HOME/.claude/skills" ;;
  codex) link "${CODEX_HOME:-$HOME/.codex}/skills" ;;
  all)
    link "$HOME/.claude/skills"
    link "${CODEX_HOME:-$HOME/.codex}/skills"
    ;;
  *) echo "usage: $0 [claude|codex|all] [skill...]" >&2; exit 1 ;;
esac
