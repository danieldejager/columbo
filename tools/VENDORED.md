# Vendored files

Files under tools/derive/ are vendored from the maintainer's own tooling.
Python standard library only; nothing in C and no third-party source.

| File | sha256 (as vendored here) |
|---|---|
| tools/derive/derive.py | 316f8d88f4cc0fee98929a27289a095936465abd23a6296a6a81cd9e23d856b4 |
| tools/derive/build_db.py | b4014b9df8d159f833fc6df7dde3312ef68a282a31ed8d546e642a98b897a592 |
| tools/derive/check_db.py | e6f7d1fd69ab27e0fe57eff614925eac4b4ee5b604294707e2fa597039bb3eb9 |
| tools/derive/probespec.py | 3e4690bad295a3b54ace74eb5b08682e74a3eaefc61d4fc2ce432ef7f3b45727 |
| tools/derive/_version.py | bcd896275e2bfdcc39b7fed40ea0d021566f95a74a146c871f66afb0ba4ded58 |

## Licence

The maintainer is the sole author of these files and has dedicated them to
the public domain under CC0 1.0 Universal, the same as the rest of this
repository. See LICENSE and NOTICE.

## Changes from upstream

Only text was changed; no logic, control flow, constant value used in a
comparison, or function signature was touched:

* private product, tool and directory names removed from docstrings,
  comments and the comment header lines that build_db.py and derive.py
  write into their output, and issue numbers removed from comments;
* the two dash characters in output strings replaced with a colon and a
  semicolon;
* the run JSON error message now says "probe run JSON";
* clean room pass on derive.py and probespec.py: every verbatim quote of the
  published method page (including its option list for the ECN probe, its
  GCD wording and its section titles) and the T2 to T7 option hex string in
  a comment were replaced with a short paraphrase plus the citation link.
  The probespec.py header and ECN comment now say the probe follows a
  published scanner method, with the ECN urgent pointer and reserved bits
  matched to observed traffic from that method. Comments and docstrings
  only; the code compares equal as a syntax tree with docstrings removed,
  and derive output is unchanged.

probespec.py is vendored because derive.py imports options_letters from it.

So derive.py, build_db.py and check_db.py behave exactly as upstream, except
that those comment lines in their output read differently. check_db.py,
probespec.py and _version.py differ from upstream only in docstrings and
comments.

Two upstream behaviours are kept as they are and worth knowing:

* derive.py re-parses a packet from its hex only for run files that lack
  urgptr (TCP) or icmp_unused (ICMP), and that path needs a parser module
  that is not vendored. Bundles from tools/scrub.py always carry both keys,
  so the path is never taken.
* build_db.py reads the derive.py commit with `git log` and expects the
  upstream capture directory layout; it is vendored for reference and is
  not wired into the checks.
