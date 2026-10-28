![Project Columbo](assets/project-columbo-logo.png)

# Columbo

Columbo is an open database of operating system fingerprints, built from real captures and released under the CC0 1.0 public domain dedication. It is free to use, with no questions asked and no strings attached.

It is made for people who build decoys, honeypots, scanners and detection tools and need accurate, well documented fingerprints they can trust and reuse.

## Repository layout

- `entries/`: one `.fp` entry plus `.provenance.json` sidecar per OS
- `bundles/`: one directory per contributor bundle (`manifest.txt` plus 6 to 20 run JSONs)
- `tools/checks/`: contribution checks (Python standard library only)
- `tools/derive/`: the step that turns a capture bundle into an entry, and builds the release database
- `tools/scrub.py`: removes identifying details from a raw capture. It is the step used on the project's own captures and is not yet a supported contributor tool
- `docs/`: check rules and entry format

## What each entry carries

- Its provenance: how it was captured, when, and on what.
- A pass from the same automated quality and security checks, before it is added.

## Current state

The first database release (v1) is being prepared and is not published yet.

More systems are on the way. The tool that prepares a capture bundle for submission is not ready yet, so bundle submissions open when it ships. Until then, the most useful things you can do are review the check rules in `docs/`, tell us what is missing, and introduce yourself.

The check that keeps similar entries apart (the sibling threshold) is provisional and may be tuned as more entries arrive.

## How it is built

Every fingerprint is captured from a system we own or have permission to test, then scrubbed of anything identifying. Contributors attest that each entry was measured from their own hosts and not copied or derived from another fingerprint database. We check this by re-running our derive step on the submitted capture bundle and by maintainer spot checks. No tool can prove it on its own. Contributions are checked automatically on every pull request. If any check fails, the pull request fails with a reason. If every check passes, a maintainer reviews it and merges it by hand.

## Get involved

Want to contribute? Please reach out to Daniel de Jager at ddejager@dandejager.com or visit [www.dandejager.com](https://www.dandejager.com) first. The address is for introductions only, so please do not send any private data by email. Then introduce yourself in the pinned "Introduce yourself" discussion. Contributions come as pull requests from your own fork, and being introduced does not give write access. We would like to know who you are, what you build, and which systems you can capture.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request.

## Privacy

Columbo contains only fingerprints captured for this project or contributed under the rules in CONTRIBUTING.md. Private data never belongs here. The checks reject IP addresses, host names, user names, secrets and personal data.

## Licence

Data and code are dedicated to the public domain under CC0 1.0 Universal; see `LICENSE` and `NOTICE`. The project name and logo are not covered.

Run the tests locally with `python3 -m pytest -q`.
