# Columbo database {{TAG}}

A release of the Columbo fingerprint database.

## What is in it

- {{ENTRY_COUNT}} entries, all captured by the project from real systems and built from scrubbed capture bundles:
{{ENTRY_LIST}}
- Each entry has a provenance file and passed the project's quality and security checks before it was added.
- The database file is built by the project's own release workflow from the entries in this repository. Nothing is added by hand.

## Verify it

- `{{DB_FILE}}`, the database.
- `{{SHA_FILE}}`, its sha256 checksum in `sha256sum` format.

The maintainer adds his own signature files to this release by hand, made on his own machine with cosign and his own key. The release workflow never signs anything.

Check the checksum and the signature before you use the file:

```
sha256sum -c {{SHA_FILE}}
```

## What is not in it

More systems are on the way. They are added as contributions that pass the checks. See CONTRIBUTING.md.

## Licence

CC0 1.0 Universal. Free to use, with no questions asked and no strings attached.
