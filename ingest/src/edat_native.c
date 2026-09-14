/* Bounded EDAT orchestration; cryptography is make-npdata (Hykem, GPL-3.0).
 * Pinned source and safety/memory patches are prepared by ingest/build.zig. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Exclude the upstream CLI, filesystem extraction and key logging. */
#define PSPDB_EDAT_CRYPTO_ONLY
#include "make_npdata.c"

#define BLOCK_SIZE 16384U

static int authenticate(const unsigned char *data, size_t size,
                        const unsigned char *tag, unsigned char *key, int hash_mode)
{
    unsigned char hash_key[16];
    generate_hash(hash_mode, 0, hash_key, key);
    /* Upstream's CMAC interface predates const; it only reads data and tag. */
    return cmac_hash_compare(hash_key, 16, (unsigned char *)data, (int)size,
                             (unsigned char *)tag);
}

/* Private FFI: edat.zig validates the complete source layout and license type,
 * and owns output. Inputs must not overlap output. No plaintext is returned by Zig on failure. */
int pspdb_edat_decode(const unsigned char *source, unsigned char *output,
                     size_t length, uint32_t version, uint32_t flags,
                     uint32_t license_type, const unsigned char *license)
{
    size_t blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    size_t metadata_size = blocks * 16;
    size_t data_offset = 0x100 + metadata_size;
    unsigned char key[16];
    if (license_type == 3)
        memset(key, 0, sizeof(key));
    else
        get_rif_key((unsigned char *)license, key);
    int mode = (flags & EDAT_ENCRYPTED_KEY_FLAG) ? 0x10000002 : 0x02;

    /* The keyed header MAC covers every NPD byte, including title_hash.
     * Filename-dependent title hashes and ECDSA signatures are not verified. */
    if (!authenticate(source, 0xa0, source + 0xa0, key, mode) ||
        !authenticate(source + 0x100, metadata_size, source + 0x90, key, mode))
        return 0;

    for (size_t block = 0; block < blocks; ++block) {
        unsigned char block_key[16] = {0};
        unsigned char derived_key[16];
        unsigned char iv[16] = {0};
        if (version == 2) {
            memcpy(block_key, source + 0x60, 12);
            memcpy(iv, source + 0x40, 16);
        }
        block_key[12] = (unsigned char)(block >> 24);
        block_key[13] = (unsigned char)(block >> 16);
        block_key[14] = (unsigned char)(block >> 8);
        block_key[15] = (unsigned char)block;
        aesecb128_encrypt(key, block_key, derived_key);

        size_t offset = block * BLOCK_SIZE;
        size_t plain_size = length - offset;
        if (plain_size > BLOCK_SIZE)
            plain_size = BLOCK_SIZE;
        size_t padded_size = (plain_size + 15) & ~(size_t)15;
        /* Only the final partial AES block needs scratch space. Full blocks
         * decrypt directly into the caller's exact-size owned allocation. */
        unsigned char final_block[BLOCK_SIZE];
        unsigned char *target = plain_size == padded_size ? output + offset : final_block;
        if (!decrypt(mode, mode, 0, (unsigned char *)source + data_offset + offset,
                     target, (int)padded_size, derived_key, iv, derived_key,
                     (unsigned char *)source + 0x100 + block * 16))
            return 0;
        if (target == final_block)
            memcpy(output + offset, final_block, plain_size);
    }
    return 1;
}
