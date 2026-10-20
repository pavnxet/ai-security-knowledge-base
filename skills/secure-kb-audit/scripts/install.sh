#!/usr/bin/env bash
# Install the secure-kb-audit skill into one or more agent harnesses.
#
# Agent Skills are just directories containing SKILL.md, so "installing" means
# placing (or symlinking) this folder where a harness looks for skills.
#
#   ./install.sh                 # install for every harness detected on this machine
#   ./install.sh --claude        # ~/.claude/skills/          (Claude Code, personal)
#   ./install.sh --agents        # ~/.agents/skills/          (Codex / OpenCode / Pi, shared)
#   ./install.sh --project       # ./.claude/skills + ./.agents/skills  (this repo only)
#   ./install.sh --all --copy    # copy instead of symlink
#   ./install.sh --dry-run       # show what would happen
#
# Symlinks are the default so that `git pull` updates every harness at once.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"          # the skill directory (contains SKILL.md)
NAME="$(basename "$SRC")"

MODE="symlink"; DRY=0; TARGETS=()

for arg in "$@"; do
  case "$arg" in
    --claude)   TARGETS+=("$HOME/.claude/skills") ;;
    --agents)   TARGETS+=("$HOME/.agents/skills") ;;
    --opencode) TARGETS+=("$HOME/.config/opencode/skills") ;;
    --pi)       TARGETS+=("$HOME/.pi/agent/skills") ;;
    --codex)    TARGETS+=("$HOME/.agents/skills") ;;
    --project)  TARGETS+=(".claude/skills" ".agents/skills") ;;
    --all)      TARGETS+=("$HOME/.claude/skills" "$HOME/.agents/skills" "$HOME/.config/opencode/skills" "$HOME/.pi/agent/skills") ;;
    --copy)     MODE="copy" ;;
    --symlink)  MODE="symlink" ;;
    --dry-run)  DRY=1 ;;
    -h|--help)  sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ ${#TARGETS[@]} -eq 0 ]; then
  # detect: only install where the harness already exists
  [ -d "$HOME/.claude" ] && TARGETS+=("$HOME/.claude/skills")
  [ -d "$HOME/.agents" ] && TARGETS+=("$HOME/.agents/skills")
  [ -d "$HOME/.config/opencode" ] && TARGETS+=("$HOME/.config/opencode/skills")
  [ -d "$HOME/.pi" ] && TARGETS+=("$HOME/.pi/agent/skills")
  if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "No harness detected. Pick one explicitly, e.g.: $0 --claude" >&2
    exit 1
  fi
fi

# sanity: the skill must be valid before we scatter it around
[ -f "$SRC/SKILL.md" ] || { echo "SKILL.md not found in $SRC" >&2; exit 1; }

for base in "${TARGETS[@]}"; do
  dest="$base/$NAME"
  if [ "$DRY" = 1 ]; then
    echo "would $MODE: $SRC -> $dest"
    continue
  fi
  mkdir -p "$base"
  rm -rf "$dest"
  if [ "$MODE" = "symlink" ]; then
    ln -s "$SRC" "$dest"
  else
    cp -R "$SRC" "$dest"
  fi
  echo "installed ($MODE): $dest"
done

echo
echo "Verify with the harness's own validator, e.g.:"
echo "  python3 -c \"import yaml,sys;d=yaml.safe_load(open('$SRC/SKILL.md').read().split('---')[1]);print(d['name'])\""
echo "Then in a session, ask: \"audit <repo> for security bugs\"."
