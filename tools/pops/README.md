# Contextual POPS executable extraction

`pspdb-pops parent.pbp output` reads the complete PBP with Zig-PSP's in-memory
reader, recovers a title key from the PS1 DATA.BIN PGD, and returns verified
DATA.PSP plaintext. It writes no keys or generated reports. The adapter detects
whether those bytes are gzip or ELF before naming them. Decoded ELF objects use
`.elf` even when their ELF type is PSP PRX (0xffa0). Gzip naming preserves the
format detected after decompression: `DATA.PSP → DATA.gz → DATA.elf`.
The PRX subtype remains in the ELF header; no conversion occurs.

Build after `zig build` has populated the ingest dependency cache:

```
ZIG_GLOBAL_CACHE_DIR=/tmp/pspdb-zig-cache python tools/build_pops.py \
  --pspdecrypt-source /path/to/pspdecrypt-git-checkout \
  --output /tmp/pspdb-pops
```

Install the output as `pspdb-pops` on PATH or set `PSPDB_POPS`. Requires Zig0.16,
a C/C++ compiler, GNU patch and Python. The build archives the exact public
pspdecrypt commit `c156627db7634d395c380c0a9589130f603307fc`; working-tree changes
in the supplied checkout are ignored. Source: https://github.com/John-K/pspdecrypt.
The only decoder change is the published POPS tag/key/XOR table entry. Existing
type5 and libkirk algorithms perform the cryptography. A separate process keeps
libkirk's mutable state isolated between concurrent jobs.

Zig-PSP's pinned `tools/prxencrypt/kirk.zig` implements command0 encryption. It
does not yet supply the command1/7 decryption or NPDRM BBMac/key-recovery APIs
needed here. Zig-PSP continues to own PBP parsing; no custom PBP parser is used.

## Supported profile and checks

Initial support is POPS_EXEC mode20, tag0DAA06F0, KIRK code0x65, PGD key index1 /
DRM type1. Other profiles fail explicitly. PSISOIMG0000 locates PGD at0x400;
PSTITLEIMG0000 locates it at0x200, but multi-disc remains untested. The helper
checks section/header bounds, declared PRX/ciphertext sizes and the DNAS MAC;
pspdecrypt then checks header SHA1 and KIRK authenticates the ciphertext.

GaiaSeed and three additional real PBPs reproduce independently verified outputs
(gzip and raw ELF variants). Earlier research exercised the underlying recipe on
six titles. Mutated ciphertext and PGD fail without producing output.

## Catalog attachment

PBP revision8 is the extraction/cache unit. Its DATA.PSP file entry carries an
optional `extraction` object containing the encrypted source's exact hash/size,
helper provenance and immediate decoded entries. The contextual result is scoped
to that PBP occurrence; it is not a globally registered PRX tree or a fake file.
The helper input is the enclosing PBP, while the attachment target remains its
DATA.PSP entry. Generated decoded bytes retain normal content-store hashes.

The website accepts the inline tree only when its source hash/size matches the
file entry. Generic gzip/ELF processing continues below it. Catalog validation,
download indexing, dependency freshness and cached-task reuse traverse the
inline children. Changing the POPS helper hash invalidates affected PBP results.
Do not reuse an old extractor revision after changing output behavior: historical
catalog results remain immutable.

## Primary references

- [JPCSP exact tag configuration](https://github.com/jpcsp/jpcsp/blob/cd20cf312b358b4260f26f6754f9c62926c70ba6/src/jpcsp/crypto/PRX.java#L260)
- [JPCSP mode20/type5](https://github.com/jpcsp/jpcsp/blob/cd20cf312b358b4260f26f6754f9c62926c70ba6/src/jpcsp/crypto/PRX.java#L440)
- [PSXtract PGD recovery and DNAS verification](https://github.com/xdotnano/PSXtract/blob/72618c6bc2c026e88e95d72700ec7d0238372d49/Windows/crypto.cpp#L43)
