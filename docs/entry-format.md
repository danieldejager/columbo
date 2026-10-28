# Entry format

Each OS has two files in `entries/`, sharing a base name equal to the entry name:

- `<name>.fp`
- `<name>.provenance.json`

## Name

The name must be one of the personas the release database accepts, the fixed
list `PERSONA_ORDER` in `tools/derive/build_db.py` (for example `win11-fwon`,
`win11-fwoff`, `ubuntu2404`). Lower case, `[a-z0-9][a-z0-9-]{0,39}`. The name
ending says the firewall state: `-fwoff` means off, anything else means on.

## `.fp` file

Printable ASCII, LF line endings, ending with a newline. Two parts and nothing
else: no blank lines and no comment lines.

1. Exactly five `#@` provenance lines, in any order, each `#@ key: value`:

   | Key | Rule |
   |---|---|
   | `name` | equals the file base name and the `Fingerprint` name |
   | `firewall` | `on` or `off`, and agrees with the name ending |
   | `runs` | integer 6 to 40, equal to the number of run files in the linked bundles |
   | `probe_version` | `N.N.N`, equal to `probe_version` in the linked bundles |
   | `derive_version` | `N.N.N`, equal to the bundle manifests and to the vendored `tools/derive` version |

   Any other `#@` key fails. Build numbers, host names, user names,
   addresses, run ids and repository links never appear in an entry.

2. The personality block exactly as `tools/derive/derive.py` renders it,
   from the `Fingerprint <name>` line to the end. derive writes comment lines
   (`#`) above the block; those are not part of an entry and must be removed.

```
#@ name: win11-fwon
#@ firewall: on
#@ runs: 6
#@ probe_version: 0.3.2
#@ derive_version: 0.3.2
Fingerprint win11-fwon
SEQ(SP=0%GCD=3D090%ISR=AA%TI=I%CI=I%II=I%SS=S%TS=7)
OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8ST11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=M5B4NW8ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)
ECN(R=Y%DF=Y%T=80%TG=80%W=FFFF%O=M5B4NW8ST11%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%TG=80%W=FFFF%S=O%A=S+%F=AS%O=M5B4NW8ST11%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%TG=80%CD=Z)
```

(Values above are from the synthetic test fixture, `tests/fixtures/pass/`.)

## Block rules

Thirteen test group lines, each once, in this order: SEQ, OPS, WIN, ECN,
T1 to T7, U1, IE. Each line is `GROUP(field=value%field=value...)`. Inside a
group, fields appear in the order derive writes them; unknown fields,
duplicate fields and missing required fields fail. ECN, T1 to T7, U1 and IE
may instead be exactly `R=N` (no reply).

All numbers are upper case hexadecimal, as derive writes them.

| Group | Fields (optional in brackets) | Value rules |
|---|---|---|
| SEQ | [SP] [GCD] [ISR] [TI] [CI] [II] [SS] [TS] | SP, ISR: hex up to FFF (derive writes eight times a base two logarithm, which passes FF on fast counters), or a range `lo-hi` with lo below hi; GCD: hex up to FFFFFFFF; TI, CI, II: Z, RD, RI, BI, I or hex up to FFFF; SS: S or O; TS: U, 0, 1, 7, 8 or hex up to 3F |
| OPS | O1 to O6 | 0 to 40 of `A-Z0-9` |
| WIN | W1 to W6 | empty or hex up to FFFF |
| ECN | R DF T TG [W] O CC Q | R: Y; DF: Y or N; T: hex 1 to 1FF; TG: 20, 40, 80 or FF; W: hex up to FFFF; O as OPS; CC: Y, N, S or O; Q: empty, R, U or RU |
| T1 to T7 | R DF T TG [W] S A F O RD Q | as ECN, plus S: Z, A, A+, S or O; A: Z, S, S+ or O; F: letters from EUAPRSF in that order, each once; RD: 0 |
| U1 | R DF T TG IPL UN RIPL RID RIPCK RUCK RUD | IPL: hex up to FFFF; UN: hex up to FFFFFFFF; RIPL, RID, RUCK: G or hex up to FFFF; RIPCK: G, Z or I; RUD: G or I |
| IE | R DFI T TG CD | DFI: N, S, Y or O; CD: Z, S, O or hex up to FF |

These rules follow the values `render_personality` in derive.py can produce.

## Fields that vary between runs

The block is derived from all runs of the linked bundles, sorted by run id.
For a field every run agrees on, that value is used. SP and ISR vary slightly
between runs (they are timing estimates), so for those two the block holds
the minimum to maximum range over all runs, exactly as
`tools/derive/build_db.py` writes it; this does not depend on run order. Any
other field that varies is refused. The block is therefore a deterministic
function of the bundle runs, not an average.

## Sidecar `.provenance.json`

A JSON object with exactly the keys `name`, `firewall`, `runs`,
`probe_version`, `derive_version`. Values must equal the `#@` lines (`runs` as
an integer, the rest as strings).

## Contributor attestation

Each pull request carries the contributor's statement that the entry was
measured from their own hosts and not copied or derived from another
fingerprint database. The checks cannot prove this; the bundle link check
and maintainer spot checks support it.
