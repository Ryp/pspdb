#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libkirk/kirk_engine.h"
#include "libkirk/amctrl.h"

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int verify_mac(const uint8_t *bytes, size_t size,
                      const uint8_t expected[16], uint8_t key[16]) {
    MAC_KEY mac;
    if (size > INT_MAX || sceDrmBBMacInit(&mac, 1) ||
        sceDrmBBMacUpdate(&mac, (uint8_t *)bytes, (int)size) ||
        sceDrmBBMacFinal2(&mac, (uint8_t *)expected, key)) {
        memset(&mac, 0, sizeof(mac));
        return 0;
    }
    memset(&mac, 0, sizeof(mac));
    return 1;
}

/* Decode only the observed fixed-key OPNSSMP profile. The caller bounds the
 * source to 64 KiB and owns an equally large output. No unauthenticated
 * plaintext is returned: header, MAC table, and every ciphertext block pass. */
int pspdb_pgd_decode(const uint8_t *source, size_t source_size,
                     uint8_t *output, size_t output_size) {
    static const uint8_t dnas_key1a90[16] = {
        0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
        0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
    };
    uint8_t header[0x90];
    uint8_t version_key[16];
    MAC_KEY mac;
    CIPHER_KEY cipher;
    int result = -4;

    if (!source || !output || source_size < 0xb0 || source_size > INT_MAX ||
        output_size < source_size || memcmp(source, "\0PGD", 4) != 0) {
        return -4;
    }
    if (read_le32(source + 4) != 1 || read_le32(source + 8) != 1) return -1;

    kirk_init_prx();
    memcpy(header, source, sizeof(header));
    if (!verify_mac(header, 0x80, header + 0x80, (uint8_t *)dnas_key1a90)) {
        result = -2;
        goto done;
    }
    if (sceDrmBBMacInit(&mac, 1) || sceDrmBBMacUpdate(&mac, header, 0x70) ||
        bbmac_getkey(&mac, header + 0x70, version_key)) {
        result = -3;
        goto done;
    }
    if (sceDrmBBCipherInit(&cipher, 1, 2, header + 0x10, version_key, 0) ||
        sceDrmBBCipherUpdate(&cipher, header + 0x30, 0x30) ||
        sceDrmBBCipherFinal(&cipher)) {
        result = -3;
        goto done;
    }

    const size_t data_size = read_le32(header + 0x44);
    const size_t block_size = read_le32(header + 0x48);
    const size_t data_offset = read_le32(header + 0x4c);
    if (data_size == 0 || data_size > SIZE_MAX - 15 || block_size < 16 ||
        block_size > (1u << 20) || (block_size & (block_size - 1)) != 0 ||
        data_offset < sizeof(header) || (data_offset & 15) != 0) {
        result = -4;
        goto done;
    }
    const size_t aligned_size = (data_size + 15) & ~(size_t)15;
    if (aligned_size > output_size || data_offset > source_size ||
        aligned_size > source_size - data_offset) {
        result = -4;
        goto done;
    }
    const size_t block_count = (aligned_size + block_size - 1) / block_size;
    if (block_count > SIZE_MAX / 16) {
        result = -4;
        goto done;
    }
    const size_t table_offset = data_offset + aligned_size;
    const size_t table_size = block_count * 16;
    if (table_offset > source_size || table_size != source_size - table_offset) {
        result = -4;
        goto done;
    }
    if (!verify_mac(source + table_offset, table_size, header + 0x60, version_key)) {
        result = -2;
        goto done;
    }
    for (size_t block = 0; block < block_count; block++) {
        const size_t offset = block * block_size;
        const size_t size = aligned_size - offset < block_size ? aligned_size - offset : block_size;
        if (!verify_mac(source + data_offset + offset, size,
                        source + table_offset + block * 16, version_key)) {
            result = -2;
            goto done;
        }
    }

    memcpy(output, source + data_offset, aligned_size);
    if (sceDrmBBCipherInit(&cipher, 1, 2, header + 0x30, version_key, 0) ||
        sceDrmBBCipherUpdate(&cipher, output, (int)aligned_size) ||
        sceDrmBBCipherFinal(&cipher)) {
        memset(output, 0, aligned_size);
        result = -3;
        goto done;
    }
    result = (int)data_size;

done:
    memset(&mac, 0, sizeof(mac));
    memset(&cipher, 0, sizeof(cipher));
    memset(version_key, 0, sizeof(version_key));
    memset(header, 0, sizeof(header));
    return result;
}
