/* Bounded NPUMDIMG orchestration using mmozeiko/pkg2zip (Unlicense), pinned
 * and patched by ingest/build.zig. LZRC is the upstream libkirk/tpu routine.
 * This route excludes the upstream CLI, filesystem, outer PKG and CSO code. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PSPDB_NPUMDIMG_MEMORY
#include "pkg2zip_psp.c"

enum {
    NPUMDIMG_OK = 0,
    NPUMDIMG_HEADER = 1,
    NPUMDIMG_UNSUPPORTED_BLOCK = 2,
    NPUMDIMG_SECTORS = 3,
    NPUMDIMG_TABLE = 4,
    NPUMDIMG_BLOCK = 5,
    NPUMDIMG_LZRC = 6,
    NPUMDIMG_OUTPUT_SIZE = 7,
    NPUMDIMG_ALLOCATION = 8
};

/* The callback is called exactly once, after the header and table span pass.
 * Its owner retains the allocation on every subsequent return, including
 * failure. It returns byte-aligned nonoverlapping storage of exactly size.
 * The callback has returned before any C-only LZRC error boundary is entered. */
typedef uint8_t* (*npumdimg_allocate)(void* context, size_t size);

int pspdb_npumdimg_decode(const uint8_t* source, size_t size,
                         npumdimg_allocate allocate, void* context)
{
    if (size < 256 || memcmp(source, "NPUMDIMG", 8) != 0)
        return NPUMDIMG_HEADER;

    uint8_t header[256];
    memcpy(header, source, sizeof(header));
    uint32_t iso_block = get32le(header + 0x0c);
    if (iso_block == 0 || iso_block > 16)
        return NPUMDIMG_UNSUPPORTED_BLOCK;

    /* Match the helper's key derivation, not an authentication guarantee. */
    uint8_t mac[16];
    aes128_cmac(kirk7_key38, header, 0xc0, mac);
    aes128_key key;
    uint8_t iv[16];
    init_psp_decrypt(&key, iv, 1, mac, header, 0xc0, 0xa0);
    aes128_psp_decrypt(&key, iv, 0, header + 0x40, 0x60);

    uint32_t iso_start = get32le(header + 0x54);
    uint32_t iso_end = get32le(header + 0x64);
    if (iso_end <= iso_start || iso_end - iso_start <= 1)
        return NPUMDIMG_SECTORS;
    uint32_t iso_total = iso_end - iso_start - 1;
    uint32_t block_count = (uint32_t)(((uint64_t)iso_total + iso_block - 1) / iso_block);
    uint32_t table_offset = get32le(header + 0x6c);
    if (table_offset % 16 || (uint64_t)table_offset + (uint64_t)block_count * 32 > size)
        return NPUMDIMG_TABLE;

    uint32_t output_block_size = iso_block * ISO_SECTOR_SIZE;
    /* Preserve the helper's full final block, even when iso_total is partial. */
    uint64_t output_size = (uint64_t)block_count * output_block_size;
    if (output_size > SIZE_MAX)
        return NPUMDIMG_OUTPUT_SIZE;
    uint8_t* output = allocate(context, (size_t)output_size);
    if (!output)
        return NPUMDIMG_ALLOCATION;

    uint8_t scratch[16 * ISO_SECTOR_SIZE];
    for (uint32_t i = 0; i < block_count; ++i) {
        const uint8_t* table = source + (size_t)table_offset + (size_t)i * 32;
        uint32_t t[8];
        for (size_t k = 0; k < 8; ++k)
            t[k] = get32le(table + k * 4);
        uint32_t block_offset = t[4] ^ t[2] ^ t[3];
        uint32_t block_size = t[5] ^ t[1] ^ t[2];
        uint32_t flags = t[6] ^ t[0] ^ t[3];
        if (!block_size || block_size > sizeof(scratch) || block_offset % 16 ||
            (uint64_t)block_offset + block_size > size ||
            (!(flags & 4) && block_size % 16))
            return NPUMDIMG_BLOCK;

        uint8_t* target = output + (size_t)i * output_block_size;
        const uint8_t* block = source + block_offset;
        if (block_size == output_block_size) {
            memcpy(target, block, block_size);
            if (!(flags & 4))
                aes128_psp_decrypt(&key, iv, block_offset / 16, target, block_size);
        } else {
            if (!(flags & 4)) {
                memcpy(scratch, block, block_size);
                aes128_psp_decrypt(&key, iv, block_offset / 16, scratch, block_size);
                block = scratch;
            }
            /* Decode directly into the owned slice. A shorter capacity than
             * upstream's scratch rejects overlong streams earlier; its exact
             * output-size check already rejected all such streams. */
            if (lzrc_decompress(target, (int)output_block_size, block, (int)block_size) !=
                (int)output_block_size)
                return NPUMDIMG_LZRC;
        }
    }
    return NPUMDIMG_OK;
}
