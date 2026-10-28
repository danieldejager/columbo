# Release gates

The repository stays private. Gate 1 is met. The others are not met yet. All must be met
before any public release.

1. Logo watermark: done for `assets/project-columbo-logo.png` (sha256 starts
   `ab762cd5`), signed off by the reviewer for that exact hash. On 28 Oct 2026 the owner
   directed that the watermark corner be painted black with nothing else changed.
   Only a small box in the bottom right differs from the original, and the file is
   a lossless PNG with no metadata. Any further edit voids the sign-off. The
   original watermarked file is not in the final tree, but earlier commits on the
   `readme-logo` branch contain it, so gate 6 (fresh squashed repository) still applies.
2. Logo metadata: re-run an image metadata check on the final logo file (an
   editor recode can add an author or tool name) and confirm it is clean.
3. Logo origin: record the origin of the clean logo in `NOTICE` or
   `tools/VENDORED.md`, and the owner confirms they claim it as the project logo.
4. Trademark and likeness: check the project name and character for trademark
   and likeness issues before going public (the owner's call).
5. Public logo formats: provide a transparent PNG or SVG for public use.
6. Fresh squashed repository: publish from a fresh repository with squashed
   history, not this working repository.
7. Full tree scan: scan every file and commit message for private terms,
   addresses, host names and secrets, and confirm a clean result.
8. Licence and owner account confirmed (CC0 1.0 proposed, not yet chosen).
9. Owner's go: nothing is public until the owner says so.
