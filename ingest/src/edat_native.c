/* Bounded EDAT orchestration; cryptography is make-npdata (Hykem, GPL-3.0).
 * Pinned source and safety/memory patches are prepared by ingest/build.zig. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Exclude the upstream CLI, filesystem extraction and key logging. */
#define PSPDB_EDAT_CRYPTO_ONLY
#include "make_npdata.c"

#define BLOCK_SIZE 16384U
#define MAX_BLOCKS 4097U

int pspdb_lz_decompress(unsigned char *out, unsigned int out_size, unsigned char *in, unsigned int in_size);

static int authenticate(const unsigned char *data, size_t size,
                        const unsigned char *tag, unsigned char *key, int hash_mode)
{
    unsigned char hash_key[16];
    generate_hash(hash_mode, 0, hash_key, key);
    /* Upstream's CMAC interface predates const; it only reads data and tag. */
    return cmac_hash_compare(hash_key, 16, (unsigned char *)data, (int)size,
                             (unsigned char *)tag);
}

static uint32_t be32(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

/* Upstream dec_section without its allocation: a compressed block's 0x20-byte
 * metadata hides {offset >> 4 tail, length, compression flag}. */
static void metadata_fields(const unsigned char *metadata, unsigned char out[16])
{
    static const unsigned char first[16] = {0xC, 0xD, 0xE, 0xF, 0x4, 0x5, 0x6, 0x7, 0xC, 0xD, 0xE, 0xF, 0x4, 0x5, 0x6, 0x7};
    static const unsigned char second[16] = {0x8, 0x9, 0xA, 0xB, 0x8, 0x9, 0xA, 0xB, 0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3};
    for (size_t i = 0; i < 16; ++i)
        out[i] = metadata[first[i]] ^ metadata[second[i]] ^ metadata[0x10 + i];
}

/* Private FFI: edat.zig validates the source layout, flags and plaintext
 * length, and owns output. Every header, metadata and block MAC is checked
 * here (block MACs before their decryption); the caller discards output on
 * failure. Inputs must not overlap output. `license` is the RIF key source
 * for license-1/2 EDATs and is ignored for SDAT and type-3 inputs. */
int pspdb_edat_decode(const unsigned char *source, size_t source_size,
                     unsigned char *output, size_t length, const unsigned char *license)
{
    if (source_size < 0x100)
        return 0;
    const uint32_t version = be32(source + 4);
    const uint32_t license_type = be32(source + 8);
    const uint32_t flags = be32(source + 0x80);
    const int sdat = (flags & SDAT_FLAG) != 0;
    const int compressed = (flags & EDAT_COMPRESSED_FLAG) != 0;
    const int interleaved = (flags & EDAT_FLAG_0x20) != 0;
    size_t blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    size_t section_size = (compressed || interleaved) ? 0x20 : 0x10;
    if (blocks >= MAX_BLOCKS || (interleaved && blocks > 1) ||
        source_size - 0x100 < blocks * section_size)
        return 0;
    size_t metadata_size = blocks * section_size;
    unsigned char key[16];
    if (sdat) {
        for (size_t i = 0; i < sizeof(key); ++i)
            key[i] = source[0x60 + i] ^ SDAT_KEY[i];
    } else if (license_type == 3) {
        memset(key, 0, sizeof(key));
    } else {
        get_rif_key((unsigned char *)license, key);
    }
    const int header_mode = (flags & EDAT_ENCRYPTED_KEY_FLAG) ? 0x10000002 : 0x02;

    /* The keyed header MAC covers every NPD byte, including title_hash.
     * Filename-dependent title hashes and ECDSA signatures are not verified. */
    if (!authenticate(source, 0xa0, source + 0xa0, key, header_mode) ||
        !authenticate(source + 0x100, metadata_size, source + 0x90, key, header_mode))
        return 0;

    int crypto_mode = (flags & EDAT_FLAG_0x02) ? 0x1 : 0x2;
    int hash_mode = !(flags & EDAT_FLAG_0x10) ? 0x02 : !(flags & EDAT_FLAG_0x20) ? 0x04 : 0x01;
    if (flags & EDAT_ENCRYPTED_KEY_FLAG) {
        crypto_mode |= 0x10000000;
        hash_mode |= 0x10000000;
    }
    unsigned char scratch[BLOCK_SIZE];
    for (size_t block = 0; block < blocks; ++block) {
        unsigned char block_key[16] = {0};
        unsigned char derived_key[16];
        unsigned char block_hash[16];
        unsigned char iv[16] = {0};
        if (version > 1) {
            memcpy(block_key, source + 0x60, 12);
            memcpy(iv, source + 0x40, 16);
        }
        block_key[12] = (unsigned char)(block >> 24);
        block_key[13] = (unsigned char)(block >> 16);
        block_key[14] = (unsigned char)(block >> 8);
        block_key[15] = (unsigned char)block;
        aesecb128_encrypt(key, block_key, derived_key);
        if (flags & EDAT_FLAG_0x10)
            aesecb128_encrypt(key, derived_key, block_hash);
        else
            memcpy(block_hash, derived_key, sizeof(block_hash));

        size_t out_offset = block * BLOCK_SIZE;
        size_t plain_size = length - out_offset;
        if (plain_size > BLOCK_SIZE)
            plain_size = BLOCK_SIZE;
        unsigned char test_hash[0x14] = {0};
        size_t offset;
        size_t stored = plain_size;
        int packed = 0;
        if (compressed) {
            const unsigned char *metadata = source + 0x100 + block * 0x20;
            unsigned char fields[16];
            metadata_fields(metadata, fields);
            uint64_t start = ((uint64_t)be32(fields) << 4) | be32(fields + 4);
            stored = be32(fields + 8);
            packed = be32(fields + 12) != 0;
            if (start > source_size)
                return 0;
            offset = (size_t)start;
            memcpy(test_hash, metadata, 0x10);
            if (packed ? (stored == 0 || stored > BLOCK_SIZE) : stored != plain_size)
                return 0;
        } else if (interleaved) {
            const unsigned char *metadata = source + 0x100;
            for (size_t i = 0; i < 0x10; ++i)
                test_hash[i] = metadata[i] ^ metadata[i + 0x10];
            offset = 0x100 + 0x20;
        } else {
            memcpy(test_hash, source + 0x100 + block * 0x10, 0x10);
            offset = 0x100 + metadata_size + block * BLOCK_SIZE;
        }
        size_t padded_size = (stored + 15) & ~(size_t)15;
        if (offset > source_size || padded_size > source_size - offset)
            return 0;
        /* Only partial AES blocks and compressed blocks need scratch space;
         * full plain blocks decrypt directly into the exact-size output. */
        unsigned char *target = (!packed && stored == padded_size) ? output + out_offset : scratch;
        if (!decrypt(hash_mode, crypto_mode, 0, (unsigned char *)source + offset,
                     target, (int)padded_size, derived_key, iv, block_hash, test_hash))
            return 0;
        if (packed) {
            if (pspdb_lz_decompress(output + out_offset, (unsigned int)plain_size, scratch, (unsigned int)padded_size) != (int)plain_size)
                return 0;
        } else if (target == scratch) {
            memcpy(output + out_offset, scratch, plain_size);
        }
    }
    return 1;
}

/* NPD dev_hash: CMAC over header[0..0x60] keyed by klicensee XOR
 * NPDRM_OMAC_KEY_2, stored at 0x60. Checked against the public klicensees
 * that retail PSP licence markers use. This authenticates header identity only;
 * the RIF-keyed header MAC at 0xa0 still needs the buyer's RAP. */
int pspdb_edat_verify_marker(const unsigned char *source)
{
    static const unsigned char zero[16] = {0};
    const unsigned char *klicensees[] = {zero, NPDRM_PSX_KEY, NPDRM_PSP_KEY_1, NPDRM_PSP_KEY_2};
    for (size_t i = 0; i < sizeof(klicensees) / sizeof(klicensees[0]); ++i) {
        unsigned char key[16];
        for (size_t j = 0; j < sizeof(key); ++j)
            key[j] = klicensees[i][j] ^ NPDRM_OMAC_KEY_2[j];
        if (cmac_hash_compare(key, 16, (unsigned char *)source, 0x60, (unsigned char *)source + 0x60))
            return 1;
    }
    return 0;
}
