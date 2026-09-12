# NPUMDIMG DATA.PSP parsing and verification

`ingest/src/data_psp.zig` parses the non-executable DATA.PSP format used with
NPUMDIMG. PBP section boundaries still come from Zig-PSP. The explicit format
context is essential: ordinary executable DATA.PSP files must not use this parser.

The parser borrows input slices and reads the 40-byte signature, padded 48-byte
content ID at 0x560, big-endian flags at 0x590, and optional little-endian OPNSSMP
offset/size fields at 0x30/0x34. It bounds-checks optional data and exposes STARTDAT
when present at 0x5a0, retaining the container unchanged. It does not decode
STARTDAT images or decrypt OPNSSMP. Unknown/reserved bytes remain in DATA.PSP.

Signature verification hashes the PBP PARAM.SFO bytes followed by the complete
48-byte content-ID field. OpenSSL libcrypto verifies the raw 20-byte r/20-byte s
ECDSA signature on the KIRK command 0x11 curve using the NPUMDIMG public key.
Curve constants follow [libkirk](https://github.com/hrydgard/ppsspp/blob/master/ext/libkirk/kirk_engine.c);
layout, signed scope and public key follow [Hykem's sign_np](https://github.com/ErikPshat/sign_np-hykem/blob/master/sign_np.c)
and its adjacent sign_np.h. No private key or signing operation is used.

Builds require OpenSSL development headers and libcrypto in addition to libarchive.
The custom curve uses OpenSSL's low-level EC interface; no EC arithmetic is
implemented in PSPDB. Objects are allocated separately for each verification,
so concurrent ingestion does not share mutable crypto state.

PBP revision 6 verifies this format before emitting any optional
OPNSSMP.PGD/STARTDAT children. Signature failure fails the input's ingest.
Generated verification reports are not extracted files and are excluded from the
inventory and content store. Revisions 4 and 5 included a generated DATA.PSP.json;
those historical catalog records remain unchanged.
The signature covers neither flags nor the whole ISO/PKG: a passing check must
not be presented as authentication of those bytes. Also, historical PSP signing
keys have been recovered, so validity is not proof of official Sony authorship.

Echochrome NPUG80135 verified with independent Python integer EC arithmetic and
with the production Zig/OpenSSL implementation. Signed SHA-1:
`d294c6860cc56de9b5b0e0b76a42ff50f9c78abc`.
Unit tests cover that signature vector, altered digest/signature, zero signature,
truncated headers, invalid optional ranges, endian handling and borrowed slices.
