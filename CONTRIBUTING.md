# Contributing to Columbo

> **Current state:** the checks described below are being added in stages. Bundle submissions are not open yet, because the tool that prepares a bundle is not ready. Please introduce yourself and review the check rules in `docs/` for now. This note comes off when submissions open.

Thank you for helping. This page tells you what we accept, how to submit it, and what happens next.

## 1. Introduce yourself first

Contributors reach out to Daniel de Jager at ddejager@dandejager.com or visit www.dandejager.com first. The address is for introductions only, so please do not email any private data. Work from a fork and open a pull request, because being invited does not give write access. Then post in the pinned "Introduce yourself" discussion: your name or handle, what you work on, and what systems you can capture. It is a short step and it helps us point you to useful work.

## 2. What we accept

- Fingerprints captured by you, from a system you own or have written permission to test.
- A completed provenance file for each entry: capture method, date, system and version, tool versions, firewall state, and at least 6 captures.
- The scrubbed capture bundle the entry was derived from: a directory `bundles/<label>/` holding `manifest.txt` and 6 to 20 `run-<uuid>.json` files, nothing else. The pipeline re-runs the derive step on it and the result must match your entry.
- A signed-off statement that the entry was measured from your own hosts.
- Entries in the documented schema only.

## 3. What we never accept

- Anything copied or derived from another fingerprint database or its output, in whole or in part.
- Captures from systems you do not own or have no permission to test.
- Anything identifying: IP addresses, host names, user names, MAC addresses, secrets, tokens or personal data.
- Data taken from a customer or third-party environment.

## 4. How to submit

1. Fork the repository and create a branch.
2. Capture and scrub using the documented tools.
3. Add your entry and its provenance file.
4. Open a pull request and fill in the checklist.

## 5. What the pipeline checks

Quality: schema and format, internal consistency, duplicates, separation from similar entries, provenance, reproducibility from your bundle, and a safe load test.
Security: identifying data and secrets, clean-room rules, and provenance present and complete.

If any check fails, the pull request fails and the report says which check and why. Fix it and push again. If every check passes, a maintainer reviews the signed head commit and merges it by hand.

The clean-room rule rests on your signed statement, the reproducibility check and maintainer spot checks. No tool can prove an entry was not copied from elsewhere, so we say so plainly.

## 6. Merge rules

- Contributors work from forks and open pull requests. Contributors never get write access.
- The required checks `data-checks` and `path-guard` must pass on every change. No exceptions and no bypass.
- A maintainer reviews the signed head commit and merges by hand. Nothing is merged automatically.
- Pull requests change data files only. Anything touching workflows, scripts or check code needs a maintainer and is never added automatically. A pull request that mixes data and other files fails.
- First-time contributors' workflow runs need a maintainer's approval.
- New entries are labelled "community, unverified" until a maintainer has reviewed them.
- A maintainer reviews every pull request, and contributors cannot merge their own.
- A maintainer also reads the pull request title, description, commit messages and branch name before merging. Please keep them free of private names, addresses and personal details, because they become public history.
- Merges are squashed. The database is published as a versioned release (`columbo-v1.db` and its checksum and signature files), built by the release workflow and signed by the maintainer on his own machine.
- Maintainers may remove an entry later if it is found to break these rules.

## 7. Licence

By contributing you agree your entry is released under the project licence, CC0 1.0, which means you dedicate your submission to the public domain. It is free to use, with no questions asked and no strings attached.

## 8. Conduct

Be kind and be specific. Report security problems privately through the security policy, not in public issues.
