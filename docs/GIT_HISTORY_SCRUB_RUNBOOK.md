# Git History Secret Scrubbing Runbook

## Context & Warning
The legacy ZAP API key (`ufmqbdsum4iqindh6jaququfso`) and previous administrator password (`Manan@123`) were eliminated from the active tree and are completely absent from `HEAD`. However, they still exist in the diffs of past historical commits (e.g. `85bd576`, `c664df2`, `4e29764`, `4d8be8d`, `0c02c32`), visible via `git log -S`.

> [!CAUTION]
> **Destructive Operation**: Scrubbing history rewrites commit hashes. This requires:
> 1. Coordinating with any other developers who have cloned this repository.
> 2. Force-pushing branches (`git push origin --force --all`).
> 3. Creating a full backup before proceeding.

Do **NOT** run this automatically during active pair programming. Follow the verified procedure below when ready to rewrite repository history.

---

## Pre-requisites
Install `git-filter-repo` (the official Git-recommended tool replacing `git filter-branch` and BFG):
```bash
# macOS via Homebrew
brew install git-filter-repo

# Or via Python / pip
pip3 install git-filter-repo
```

---

## Step 1: Create a Full Bare Backup
```bash
cd /Users/manan/Desktop/Projects
git clone --mirror Threat-Hunting-Platform Threat-Hunting-Platform-backup.git
```

---

## Step 2: Prepare Replacement Expressions
Create a text file specifying exact replacements so commit metadata and file structures remain intact while the strings are sanitized:

```bash
cd /Users/manan/Desktop/Projects/Threat-Hunting-Platform

cat << 'EOF' > scrub_expressions.txt
ufmqbdsum4iqindh6jaququfso==>[REDACTED_HISTORICAL_ZAP_KEY]
Manan@123==>[REDACTED_HISTORICAL_ADMIN_PASSWORD]
EOF
```

---

## Step 3: Execute `git-filter-repo`
Run `git-filter-repo` to replace all historical occurrences across all branches, tags, and commits:

```bash
git filter-repo --replace-text scrub_expressions.txt --force
```

---

## Step 4: Verify History Scrubbing
Confirm that `git log -S` returns zero results for both leaked strings:

```bash
git log -S "ufmqbdsum4iqindh6jaququfso" --oneline
# Expected output: (empty)

git log -S "Manan@123" --oneline
# Expected output: (empty)
```

Verify that replaced markers appear in their place:
```bash
git log -S "[REDACTED_HISTORICAL_ZAP_KEY]" --oneline
git log -S "[REDACTED_HISTORICAL_ADMIN_PASSWORD]" --oneline
```

---

## Step 5: Re-add Git Remote & Force Push
`git-filter-repo` automatically deletes remotes as a safety measure to prevent accidental pushes. Re-add your origin and force push:

```bash
# Re-link remote
git remote add origin git@github.com:Decoder420/DecodeX-Threat-Hunting-Platform.git
# Or HTTPS:
# git remote add origin https://github.com/Decoder420/DecodeX-Threat-Hunting-Platform.git

# Push all rewritten branches and tags
git push origin --force --all
git push origin --force --tags
```

---

## Step 6: Inform Collaborators
Any collaborator with an existing clone should re-clone the repository fresh:
```bash
git clone git@github.com:Decoder420/DecodeX-Threat-Hunting-Platform.git
```
*(Do not pull or merge old clones into the rewritten history, as Git would merge the old commit objects back).*
