# Scrubbing a probe bundle

tools/scrub.py turns a raw probe output directory into a bundle directory that
the bundle checks accept. It uses the Python standard library only.

## Running it

    python3 tools/scrub.py RAW_DIR OUT_DIR --label LABEL --firewall on|off [--restart 0|1] [--report FILE]

OUT_DIR must not exist yet, and its last path part should be the label. The
tool runs the bundle checks on what it wrote, prints the number of runs and
check errors, and exits 1 if any check fails. The optional report holds
counts only.

## What it reads and writes

It reads only the run-*.json files in RAW_DIR. It writes:

* manifest.txt, built from allowed keys only: label, firewall, restart, runs,
  the port numbers when every run agrees, probe_version from the runs, and
  derive_version from tools/derive;
* one run-<uuid>.json per run. The uuid has valid version 4 form and comes
  from a seeded hash of the cleaned run, so the same input always gives the
  same names.

## What it changes

* Keys the bundle schema does not allow are dropped, at every level: for
  example summary, cmdline, dry_run, probe_plan, probe_method_doc,
  timestamp, icmp_id and icmp_seq.
* tool is set to "probe" and target to 192.0.2.1. Every other address is
  mapped to another 192.0.2.x address, in the IP header and in a quoted probe.
* ICMP echo id and sequence bytes are set to zero, and icmp_unused with them.
* Bytes after the IP total length (link layer padding) are removed.
* IP, TCP, UDP and ICMP checksums are recomputed. The checksums inside a
  quoted probe move by the same step as the sent probe's checksums, so a
  quote that matched the probe still matches it and one that differed still
  differs by the same amount.
* A null parsed field the rebuild needs (such as ip_len) is filled from the
  packet header.
* Home directory user names (/home/NAME, /Users/NAME, C:\Users\NAME) are
  replaced with "user", and M= MAC vendor prefixes are removed.

It never changes probe or reply fields that describe the target's behaviour,
and it never relaxes a check: if a cleaned bundle still fails, the failing
rule is reported and the bundle is not accepted.

## What it never copies

nmap.txt, nmap.xml, p0f files, logs, packet captures and any other file in
the raw directory. Only the run JSON content above is ever carried over.

## Derive gate

tools/scrub.py also offers derive_text(), which runs the vendored derive.py on
a set of runs with run ids replaced by their position. The tests check that
derive output is identical before and after scrubbing, and that derive does
not read icmp_id or icmp_seq.
