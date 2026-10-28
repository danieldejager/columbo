# Check rules (Workflow 1, PR (a) scope)

All checks are fail closed: an error, crash, timeout or missing report is a failure.
Check code always comes from the base branch. The PR head is read as data only.

## Path rule and change classes
Changed files are read from `git diff --raw` between base and head. Every PR
falls into one class, written to the report as `change_class`:

| Class | Paths changed | Result | `auto_merge_eligible` |
|---|---|---|---|
| `data` | only `entries/` and `bundles/` | fully checked; pass or fail on the checks below | `true` if every check passes |
| `maintainer` | only other paths (workflows, `tools/`, `tests/`, docs and so on) | pass, with the line `maintainer-only change: not eligible for auto-merge; code-owner review required` | always `false` |
| `mixed` | both | fail; split into a data PR and a maintainer PR | `false` |

Code-owner review remains the gate for maintainer PRs. The later merge job reads
`auto_merge_eligible` from the report.

Always fail, in any class:

- Symlinks (mode 120000), submodules (mode 160000 or `.gitmodules`).
- Path tricks: `..` segments, absolute paths, backslashes, non-ASCII or control
  characters, and paths that collide with another path in the tree when
  case-folded or Unicode-normalised.

Data paths allowed (mode 100644 only), anything else under `entries/` or `bundles/` fails:

- `entries/<name>.fp`, `entries/<name>.provenance.json` (`<name>` lower case `[a-z0-9][a-z0-9-]{0,39}`)
- `bundles/<label>/manifest.txt`, `bundles/<label>/run-<uuid>.json`

## Entry checks
- Schema and format per `docs/entry-format.md`: ASCII, LF, only the five allowed
  `#@` keys, then the derive personality block with every required group and
  field present, no unknown or duplicate fields, values in range.
- Name: one of the release personas (`PERSONA_ORDER` in `tools/derive/build_db.py`).
- Internal consistency: file name, `#@ name` and `Fingerprint` line agree; firewall
  agrees with the name ending; sidecar present and equal to the `#@` lines.
- Provenance: runs 6 to 40 (3 to 40 for an entry without a bundle, below), probe and derive versions `N.N.N`, firewall `on` or `off`.
- Duplicate name (case-insensitive) against all other entries.
- Duplicate fingerprint: every field identical to another entry.
- Sibling separation: a new or changed entry must differ from every other entry in
  at least 2 fields of the full field set. Fields are compared as `GROUP.FIELD`
  pairs over the union of both entries' fields; a field present in one entry and
  absent in the other counts as a difference. The threshold of 2 is provisional.

## Entries without a bundle
One entry was measured by the project before capture bundles were published:
`ubuntu2404` (3 runs from one boot, no capture bundle published). It is listed
in `NO_BUNDLE_ENTRIES` in `tools/checks/entry.py` by exact name. While no
linked bundle is in the pull request it skips the bundle to entry link check,
and its run minimum is 3 instead of 6. Every other check still applies:
format, `#@` lines, sidecar equality, block parse, private string scan and
sibling separation. The list is closed; no other name, prefix or pattern is
exempt, and a new entry always needs its bundle.

## Bundle to entry link
Every new or changed entry `<name>` must come in the same pull request as its
bundle `bundles/<name>/`, also new or changed in that pull request. A bundle
`bundles/<name>-restart/` changed in the same pull request is linked too. A
bundle that is only in the base branch does not count. If no linked bundle
changed, the entry fails (fail closed). Then:

- each linked manifest's `firewall`, `probe_version` and `derive_version` equal the entry's;
- the entry's `runs` equals the total number of run files in the linked bundles;
- the entry's `derive_version` equals the vendored `tools/derive` version;
- the base branch's `tools/derive/derive.py` is run on all linked run files,
  sorted by run id. SP and ISR become the minimum to maximum range over the runs,
  as `tools/derive/build_db.py` does; any other field that varies between runs
  fails. The rendered block, from the `Fingerprint` line on, must equal the
  entry block byte for byte. Any error while deriving fails.

The rule also runs the other way: a bundle `bundles/<name>/` or
`bundles/<name>-restart/` that is added, changed or deleted in a pull request
requires both `entries/<name>.fp` and `entries/<name>.provenance.json` to change
(and not be deleted) in the same pull request, and the link check above then runs
on that entry. A changed bundle without both entry files fails (fail closed).

Entries and bundles are both data paths, so this keeps such pull requests in the
`data` class.

## Release build
`.github/workflows/release.yml` runs by hand only (`workflow_dispatch`, a tag such as
`v1`). On `main` it checks every entry (the entry checks above plus sibling
separation between all entries), turns each entry into a block with a
`#@ persona:` line and assembles them with `build_db.assemble`, runs
`tools/derive/check_db.py` with the entry names as the expected list, writes a
`sha256sum` file, and creates a draft release with exactly
`columbo-<tag>.db` and `columbo-<tag>.db.sha256`. The entry count and names in the
release notes are read from the built database. Any failure stops the job.

## Bundle schema (plan section 3)
A bundle is a directory `bundles/<label>/` with exactly one `manifest.txt` and
6 to 20 `run-<uuid>.json` files. Nothing else is allowed (no `tool-versions.txt`,
logs, captures or derive output); unknown files fail.

`manifest.txt`: ASCII, LF, one `key=value` per line, no free text. Allowed keys
and rules:

| Key | Rule |
|---|---|
| `label` (required) | `[a-z0-9-]{1,40}`, equals the directory name |
| `firewall` (required) | `on` or `off` |
| `restart` | `0` or `1` |
| `runs` (required) | integer 6 to 20, equals the number of run files |
| `run_gap_s` | integer 300 to 3600 |
| `open_tcp`, `closed_tcp`, `closed_udp` | integer 0 to 65535, equal to `ports` in every run JSON |
| `probe_version`, `derive_version` (required) | `N.N.N` |
| `python_version`, `scapy_version` | dotted version numbers |
| `arch` | `aarch64` or `x86_64` |

Any other key fails, including `kernel`, `target_os_build` and the other keys the
plan drops. Duplicate keys fail.

## Run JSON schema
Every key at every depth is on an allow-list with a value rule
(`tools/checks/bundle.py`). Unknown keys fail. `cmdline`, `timestamp`,
`probe_plan` and `dry_run` always fail.

- `run_id`: lower-case random (version 4) UUID, equal to the UUID in the file name.
- `run_index`: integer 0 to 99. `tool_version`: `N.N.N`.
- `tool`: must be exactly `probe`. The scrub tool rewrites the probe tool's own
  name to this neutral value before submission.
- `target`: must be `192.0.2.1`.
- `ports`: `open_tcp`, `closed_tcp`, `closed_udp` as integers 0 to 65535 (strings fail).
- `exchanges`: 1 to 256 items. Closed sets only:
  - `name`: SEQ1 to SEQ6, ECN, IE1, IE2, T2 to T7, U1.
  - `kind`: `ecn`, `icmp`, `syn_seq`, `tcp_unusual`, `udp`.
  Times are numbers 0 to 86400. `timeout` is a boolean.
- `sent`, `reply` (packet hex): lower-case, even length, at most 1500 bytes;
  `len` equals the byte count. The packet must start with byte `45` (IPv4 with a
  20-byte header), its length must equal the IP total length field exactly (no
  trailer or link padding; the scrub tool strips it), the protocol must be TCP,
  UDP or ICMP, and both addresses must be in documentation ranges.
- `sent_parsed`, `reply_parsed`: allow-listed keys with per-key rules.
  - `flags`: empty (the null probe, T2) or distinct letters from `FSRPAUEC`.
  - `options_raw`: a short list of `[name, value]` pairs; option names are
    EOL, MSS, NOP, SAckOK, Timestamp, WScale.
  - `ip_src` and `ip_dst` in 192.0.2.0/24.
  - `icmp_id` and `icmp_seq` are not used by derive and are not allowed; the
    scrub tool drops them.
  - Decode check: the header fields decoded from the matching packet hex must
    equal the parsed values (IP: id, ttl, df, length, tos, addresses; TCP: ports,
    seq, ack, window, flags, flags_bits, urgent pointer; UDP: ports; ICMP: type
    and code). Changing hex bytes while leaving the parsed fields alone fails.
    Option bytes and payload are not yet compared with `options_raw`.

Leak scan, character allow-list, reproducibility and loader checks arrive in
PR (c).

## Packet rebuild rule

Every packet's bytes must equal a packet rebuilt from its parsed fields, byte for
byte. Nothing in the hex may be free: a byte is either derived from a parsed field,
fixed by a rule below, or a checksum that is recomputed. Code: `rebuild_packet` and
`_payload` in `tools/checks/bundle.py`. Tests: `tests/test_packet_rebuild.py` and
`tests/test_packet_payload.py`.

Required parsed fields: `l4`, `ip_src`, `ip_dst`, `ip_id`, `ip_ttl`, `ip_df`, `ip_len`,
plus `sport`, `dport`, `seq`, `ack`, `window` for TCP, `sport`, `dport` for UDP and
`icmp_type`, `icmp_code` for ICMP. A packet without them fails ("cannot rebuild").

- IPv4: first byte 0x45, TOS 0 (or the probe field pin below), DF from `ip_df`, MF and fragment offset zero, header
  checksum valid.
- TCP: header from the parsed fields, flags from `flags_bits` (or `flags`), reserved
  bits zero, urgent pointer from the allow-list {0} even when URG is set (both
  only differ under the probe field pin below), option bytes
  equal `options_raw` re-encoded plus zero padding only, no payload, checksum valid
  over the pseudo header.
- UDP: payload empty or the U1 probe shape (300 bytes of `C`), length exact,
  checksum valid and non-zero.
- ICMP: bytes 4 to 7 come from `icmp_unused` (0 if absent), checksum valid.
- Strict allow-listed fields that the rebuild takes as given: `icmp_unused` and, for
  a destination unreachable quote, `embedded_ip_ttl`, `embedded_ip_id`,
  `embedded_ip_len`, `embedded_ip_sum` and `embedded_udp_sum`.

### Probe field pins

The probe set follows a published scanner method. Two of its probes carry
fixed non zero header fields, the same in every run: IE2's TOS comes from the
method's description, and ECN's urgent pointer and reserved bits are matched
to observed traffic from that method. They are facts about a probe, not
database text. One reply carries a pinned value too: the reply to the ECN
probe may have IP TOS 2, as measured on servers that echo ECN. These are the
only non zero TOS, urgent pointer and reserved bit values accepted anywhere. Code: `PROBE_FIELD_PINS` and
`probe_pin` in `tools/checks/bundle.py` (the only place the values live).
Tests: `tests/test_probe_pins.py`.

| Probe name | Exchange kind | Packet | l4 | Flags | IP TOS | TCP urgent pointer | TCP reserved bits |
|---|---|---|---|---|---|---|---|
| ECN | ecn | sent | tcp | SEC | 0 | 63477 | 4 |
| IE2 | icmp | sent | icmp | (none) | 4 | (not TCP) | (not TCP) |
| ECN | ecn | reply | tcp | (any) | 0 or exactly 2 | 0 | 0 |
| any other, or any other reply | any | any | any | any | 0 | 0 | 0 |

- A pin applies only when name, kind, sent packet, l4 and flags all match.
  The values are exact; there are no ranges.
- Under a pin the packet must carry exactly the pinned values: ECN with urgent
  pointer 63476, reserved bits other than 4 or a non zero TOS fails, and IE2
  with TOS 0 or 5 fails.
- The same values on any other probe, kind, flags or on a reply fail as before.
- The ECN reply pin is `REPLY_FIELD_PINS` in `tools/checks/bundle.py`. A reply
  TOS of 1, 3 or any value other than 0 or 2 fails, and TOS 2 on any other
  reply or on a sent packet fails.
- The rebuild takes TOS and reserved bits from the parsed fields only when they
  equal the pin, so the packet bytes still have to equal the rebuild; no check
  is skipped.

Decisions (taken the safe way):

- Destination unreachable quote: kept, but only when its bytes are fully rebuilt from
  this exchange's own U1 probe packet. The quote is the first `ip_len - 28` bytes of
  the probe, at least the IPv4 and UDP headers, with only the allow-listed embedded
  fields substituted. Any other byte fails.
- IE1 and IE2 echo padding: allowed only as zero bytes of length 0, 120 or 150, chosen
  by `ip_len`. Any other length or pattern fails. Other ICMP types carry no payload.

## Keeping private strings out of data files

No secret is used anywhere in this repository or its workflows. What keeps private strings out of data files:

- Filename rules: only the four data file names listed above are allowed under
  `entries/` and `bundles/`, with tight character sets (see `tools/checks/paths.py`
  and `tests/test_path_classes.py`).
- Closed value sets: every key at every depth is on an allow-list with a value rule,
  and free text has nowhere to go. Unknown keys or values fail.
- Fake values only: addresses must be in documentation ranges, `target` is fixed,
  and every packet is rebuilt from its parsed fields with all checksums verified,
  so no byte can carry hidden content.
- path-guard (below) keeps data PRs and code PRs apart, so data is always judged by
  the checks workflow from main.

## Workflow 2: path-guard

Code: `tools/checks/path_guard.py`, reusing the classes in `tools/checks/paths.py`.
Tests: `tests/test_path_guard.py`. Wiring: `.github/workflows/path-guard.yml`.

- Why: the checks workflow that runs on a pull request is the PR's own copy, so a PR
  that edits `checks.yml` could pass data checks unchecked. path-guard runs from
  main (`workflow_run`), checks out main only and runs nothing from the PR.
- It asks GitHub's compare API (`main...head`) for the changed files. A rename counts
  both its old and its new path.
  - Data only (`entries/`, `bundles/`): pass. Because the PR does not touch
    `checks.yml`, its checks run used main's copy.
  - Code only: pass with a notice; maintainer review gates it.
  - Mixed: fail. Empty: fail.
  - Bad data filenames fail here too.
- Fail closed: no token, any API or network error, a non-200 response, a compare
  status other than `ahead` or `diverged`, unreadable data or a change set of 250
  files or more gives failure.
- It runs after every checks run for a PR, whatever its result, and posts the commit
  status `path-guard` (success or failure) on the PR head. It is a required status on `main`.
- Permissions: `contents: read`, `statuses: write`. No secret, no artifact.
- A data-only PR cannot change `checks.yml`, so its checks already run main's code on
  its data.
- `workflow_run` workflows only run from the default branch, so this takes effect
  once merged to main and cannot be exercised on the PR that adds it.
- Because `path-guard` is a required status, a PR that renames or deletes the checks
  workflow gets no status and is blocked.

## Sibling threshold

`MIN_SIBLING_DISTANCE` in `tools/checks/entry.py` is 2, counted over the full
field set. This threshold is provisional. The plan specifies 3; the value will be
set once real entries show how far apart distinct systems are.
