# Using the Columbo database

`columbo-v1.db` is a personality file: a plain text list of `Fingerprint` blocks, one per operating system. A decoy tool that reads this format (honeyd is the usual example) loads the file and answers network probes the way that operating system would. Each block is also easy to read by hand.

## 1. Check the download

With `cosign.pub` and the release files in one folder:

```
sha256sum -c columbo-v1.db.sha256
cosign verify-blob --key cosign.pub --signature columbo-v1.db.sig columbo-v1.db --insecure-ignore-tlog=true
```

The second command must print `Verified OK`. The flag is needed because the signature is deliberately not recorded in a public log.

## 2. See what is inside

```
grep '^Fingerprint' columbo-v1.db
```

v1 holds six entries:

| Name | System | Firewall |
|---|---|---|
| `win11-fwon` | Windows 11 | on |
| `win11-fwoff` | Windows 11 | off |
| `ws2019-fwoff` | Windows Server 2019 | off |
| `ws2022-fwoff` | Windows Server 2022 (measured with port 3389 open) | off |
| `ws2025-fwoff` | Windows Server 2025 | off |
| `ubuntu2404` | Ubuntu 24.04 | on |

A name ending in `-fwoff` means the system's firewall was off when it was measured. Any other name means it was on.

## 3. Use it in a decoy config

A honeyd config that gives two decoys different identities. The name in `personality` must be one of the six names above.

```
create windows11
set windows11 personality "win11-fwoff"
set windows11 default tcp action reset
add windows11 tcp port 445 open
add windows11 tcp port 3389 open
bind 192.0.2.50 windows11

create server2022
set server2022 personality "ws2022-fwoff"
set server2022 default tcp action reset
add server2022 tcp port 3389 open
bind 192.0.2.51 server2022
```

Start it by giving the loader the database file with `-p`:

```
honeyd -d -p columbo-v1.db -f honeyd.conf 192.0.2.50 192.0.2.51
```

This command has not been tested against every honeyd build. The loader reads exactly one personality file. Systems that exist only in another database are not available while this file is loaded.

## 4. Check your config before you run it

This repository includes a checker. It confirms that every personality your config names exists in the database. It checks personality names only, not whether the config as a whole is valid:

```
python tools/derive/check_db.py columbo-v1.db --config honeyd.conf
```

It prints `check_db.py: OK` and exits 0 when the names all exist. A wrong name stops it with a line such as `honeyd.conf:9: personality 'ws2099' is not in the database` and exit code 1.

## Notes

- The entry gives the network stack's answers to probes. Which ports you open in the config is up to you; `ws2022-fwoff` was measured with port 3389 open, and the Server 2019 and 2025 entries with port 135 open.
- `ubuntu2404` comes from three runs on one boot and has no published capture bundle. The other five passed the repository's checks, including a re-derivation from their published capture bundles.
- To add your own system, see `docs/entry-format.md` and `docs/scrub.md`.
