#!/usr/bin/env bash
# merge-nonbreaking.sh
# Safe merge script: merges open PRs that are NOT labeled "major" or "breaking-change"
# and only when CI status is "success" and PR is mergeable.
#
# Requirements: gh (GitHub CLI) logged in, jq
#
# Usage:
#  ./merge-nonbreaking.sh                # dry-run (shows what WOULD be merged)
#  ./merge-nonbreaking.sh --apply       # actually merge
#  ./merge-nonbreaking.sh --repo owner/repo  # target a different repository
#  ./merge-nonbreaking.sh --help

set -euo pipefail

DEFAULT_REPO="Decoder420/DecodeX-Threat-Hunting-Platform"

APPLY=0
REPO="$DEFAULT_REPO"

print_help() {
  cat <<EOF2
Usage: $0 [--apply|-y] [--repo owner/repo] [--help]

--apply, -y        Actually perform merges. Without this flag the script runs in dry-run mode.
--repo owner/repo  Repository to operate on (default: $DEFAULT_REPO)
--help             Show this help message
EOF2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply|-y) APPLY=1; shift ;;
    --repo) REPO="$2"; shift 2 ;;
    --help) print_help; exit 0 ;;
    *) echo "Unknown arg: $1"; print_help; exit 1 ;;
  esac
done

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: gh (GitHub CLI) is required. Install from https://cli.github.com/"
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required. Install via your package manager."
  exit 2
fi

echo "Repository: $REPO"
if [[ $APPLY -eq 0 ]]; then
  echo "Mode: DRY RUN (no merges). Re-run with --apply to perform merges."
else
  echo "Mode: APPLY (will attempt to merge eligible PRs)."
fi
echo

skip_reasons=()
to_merge=()

pr_list_json=$(gh pr list --repo "$REPO" --state open --json number,title,labels 2>/dev/null || true)

if [[ -z "$pr_list_json" || "$pr_list_json" == "[]" ]]; then
  echo "No open pull requests found."
  exit 0
fi

echo "Scanning open PRs..."
echo

# Iterate PRs using process substitution to avoid subshell array scoping issues
while read -r pr; do
  [[ -z "$pr" ]] && continue
  num=$(jq -r '.number' <<<"$pr")
  title=$(jq -r '.title' <<<"$pr")
  label_names=$(jq -r '[.labels[].name] | join("|")' <<<"$pr")
  echo "PR #$num: $title"
  echo "  Labels: ${label_names:-(none)}"

  if [[ "$label_names" =~ major ]] || [[ "$label_names" =~ -?breaking ]]; then
    reason="skipped (labelled major/breaking)"
    echo "  -> $reason"
    skip_reasons+=("#$num: $reason")
    echo
    continue
  fi

  mergeable=$(gh pr view "$num" --repo "$REPO" --json mergeable --jq .mergeable 2>/dev/null || echo "UNKNOWN")
  headsha=$(gh pr view "$num" --repo "$REPO" --json headRefOid --jq .headRefOid 2>/dev/null || echo "")

  if [[ -z "$headsha" ]]; then
    reason="skipped (couldn't determine PR head SHA)"
    echo "  -> $reason"
    skip_reasons+=("#$num: $reason")
    echo
    continue
  fi

  if [[ "$mergeable" == "CONFLICTING" || "$mergeable" == "conflicting" ]]; then
    reason="skipped (merge conflicts)"
    echo "  -> $reason"
    skip_reasons+=("#$num: $reason")
    echo
    continue
  fi
  if [[ "$mergeable" == "UNKNOWN" || "$mergeable" == "unknown" ]]; then
    reason="skipped (mergeable=UNKNOWN)"
    echo "  -> $reason"
    skip_reasons+=("#$num: $reason")
    echo
    continue
  fi

  combined_state=$(gh api "repos/${REPO}/commits/${headsha}/status" --jq '.state' 2>/dev/null || echo "unknown")
  echo "  Commit status: ${combined_state}"

  if [[ "$combined_state" != "success" ]]; then
    reason="skipped (CI status=${combined_state})"
    echo "  -> $reason"
    skip_reasons+=("#$num: $reason")
    echo
    continue
  fi

  echo "  -> Eligible for merge"
  to_merge+=("$num")
  echo
done < <(echo "$pr_list_json" | jq -c '.[]')

echo
echo "Summary:"
echo "Eligible PRs to merge: ${#to_merge[@]}"
if [[ ${#to_merge[@]} -gt 0 ]]; then
  for n in "${to_merge[@]}"; do
    echo "  - #$n"
  done
else
  echo "  (none)"
fi
echo
if [[ ${#skip_reasons[@]} -gt 0 ]]; then
  echo "Skipped PRs:"
  for s in "${skip_reasons[@]}"; do
    echo "  - $s"
  done
  echo
fi

if [[ ${#to_merge[@]} -eq 0 ]]; then
  echo "No eligible PRs to merge. Exiting."
  exit 0
fi

if [[ $APPLY -eq 0 ]]; then
  echo "Dry-run complete. Re-run with --apply to perform the merges."
  exit 0
fi

read -r -p "Proceed to merge ${#to_merge[@]} PR(s)? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  echo "Aborting: user cancelled."
  exit 0
fi

merged=()
failed=()
for n in "${to_merge[@]}"; do
  title=$(gh pr view "$n" --repo "$REPO" --json title --jq .title)
  echo "Merging PR #$n - $title"
  if gh pr merge "$n" --repo "$REPO" --merge --subject "Merge PR #$n: $title" --body "Auto-merged non-breaking PR by script"; then
    echo "  -> Merged #$n"
    merged+=("#$n")
  else
    echo "  -> FAILED to merge #$n"
    failed+=("#$n")
  fi
done

echo
echo "Done."
echo "Merged: ${#merged[@]}"
for m in "${merged[@]}"; do echo "  $m"; done
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "Failed: ${#failed[@]}"
  for f in "${failed[@]}"; do echo "  $f"; done
fi
