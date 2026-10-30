#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libkirk/kirk_engine.h"
#include "libkirk/amctrl.h"

/* Empty-key PGD decryption for PS1 Classic DATA.PSAR, following PSXtract-2's
 * decrypt_pgd (flag 2: DNAS key 1A90) with these deliberate differences:
 * every field is bounds-checked, and every per-block MAC is verified before any
 * plaintext is produced. The source is never modified. libkirk state is
 * thread-local in the pinned patched build, so concurrent calls are safe. */

enum {
    PGD_OK_MIN = 0,
    PGD_INVALID = -1,
    PGD_HEADER_MAC = -2,
    PGD_CIPHER = -3,
    PGD_BAD_ARGUMENT = -4,
    PGD_TABLE_MAC = -5,
    PGD_BLOCK_MAC = -6,
    PGD_KEY = -7,
};

static const uint8_t dnas_key1a90[16] = {
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
    0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
};

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int verify_mac(int mac_type, const uint8_t *bytes, size_t size,
                      const uint8_t expected[16], const uint8_t key[16]) {
    MAC_KEY mac;
    int failed;
    if (size == 0 || size > INT_MAX) return 0;
    failed = sceDrmBBMacInit(&mac, mac_type) ||
        sceDrmBBMacUpdate(&mac, (uint8_t *)bytes, (int)size) ||
        sceDrmBBMacFinal2(&mac, (uint8_t *)expected, (uint8_t *)key);
    memset(&mac, 0, sizeof(mac));
    return !failed;
}

/* Returns data_size (> 0) on success with the plaintext in out[0..data_size),
 * or a negative PGD_* code. out must hold at least the 16-aligned data size;
 * out_size smaller than that is PGD_BAD_ARGUMENT. */
int pspdb_psx_pgd_decrypt(const uint8_t *source, size_t source_size,
                          uint8_t *output, size_t output_size) {
    uint8_t header[0x90];
    uint8_t version_key[16];
    MAC_KEY mac;
    CIPHER_KEY cipher;
    int result = PGD_INVALID;
    int mac_type, cipher_type;

    if (!source || !output || source_size < 0x90 || source_size > INT_MAX) {
        return PGD_BAD_ARGUMENT;
    }
    kirk_init_prx();
    memcpy(header, source, sizeof(header));

    /* drm_type 1 selects mac/cipher 1 (3 when key_index > 1); anything else
     * selects mac/cipher 2, exactly as PSXtract. */
    if (read_le32(header + 8) == 1) {
        mac_type = read_le32(header + 4) > 1 ? 3 : 1;
        cipher_type = 1;
    } else {
        mac_type = 2;
        cipher_type = 2;
    }

    if (!verify_mac(mac_type, header, 0x80, header + 0x80, dnas_key1a90)) {
        result = PGD_HEADER_MAC;
        goto done;
    }
    if (sceDrmBBMacInit(&mac, mac_type) || sceDrmBBMacUpdate(&mac, header, 0x70) ||
        bbmac_getkey(&mac, header + 0x70, version_key)) {
        result = PGD_KEY;
        goto done;
    }
    if (sceDrmBBCipherInit(&cipher, cipher_type, 2, header + 0x10, version_key, 0) ||
        sceDrmBBCipherUpdate(&cipher, header + 0x30, 0x30) ||
        sceDrmBBCipherFinal(&cipher)) {
        result = PGD_CIPHER;
        goto done;
    }

    {
        const uint64_t data_size = read_le32(header + 0x44);
        const uint64_t block_size = read_le32(header + 0x48);
        const uint64_t data_offset = read_le32(header + 0x4c);
        uint64_t aligned_size, block_count, table_offset, remaining;

        /* PSXtract decrypts from 0x90 regardless of data_offset; a PGD with any
         * other offset would be inconsistent, so reject it. */
        if (data_size == 0 || block_size == 0 || (block_size & (block_size - 1)) != 0 ||
            data_offset != 0x90) {
            goto done;
        }
        aligned_size = (data_size + 15) & ~(uint64_t)15;
        block_count = (aligned_size + block_size - 1) / block_size;
        if (data_offset > source_size) goto done;
        remaining = source_size - data_offset;
        if (aligned_size > remaining || block_count > (remaining - aligned_size) / 16) goto done;
        if (aligned_size > output_size) {
            result = PGD_BAD_ARGUMENT;
            goto done;
        }
        table_offset = data_offset + aligned_size;

        if (!verify_mac(mac_type, source + table_offset, (size_t)block_count * 16,
                        header + 0x60, version_key)) {
            result = PGD_TABLE_MAC;
            goto done;
        }
        for (uint64_t block = 0; block < block_count; block++) {
            const uint64_t offset = block * block_size;
            const uint64_t left = aligned_size - offset;
            const uint64_t size = left < block_size ? left : block_size;
            if (!verify_mac(mac_type, source + data_offset + offset, (size_t)size,
                            source + table_offset + block * 16, version_key)) {
                result = PGD_BLOCK_MAC;
                goto done;
            }
        }

        memcpy(output, source + data_offset, (size_t)aligned_size);
        if (sceDrmBBCipherInit(&cipher, cipher_type, 2, header + 0x30, version_key, 0) ||
            sceDrmBBCipherUpdate(&cipher, output, (int)aligned_size) ||
            sceDrmBBCipherFinal(&cipher)) {
            memset(output, 0, (size_t)aligned_size);
            result = PGD_CIPHER;
            goto done;
        }
        result = (int)data_size;
    }

done:
    memset(&mac, 0, sizeof(mac));
    memset(&cipher, 0, sizeof(cipher));
    memset(version_key, 0, sizeof(version_key));
    memset(header, 0, sizeof(header));
    return result;
}
