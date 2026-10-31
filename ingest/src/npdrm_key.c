#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libkirk/kirk_engine.h"
#include "libkirk/amctrl.h"

/* PSP "version key" of a PSN EBOOT.PBP, taken from the head of its DATA.PSAR.
 * The key is the bbmac_getkey() recovery of the protected header's own MAC, so
 * no licence is involved. Two header families carry it:
 *   NPUMDIMG        header MAC at +0xC0 over [0, 0xC0), MAC type 3
 *                   (PSP games, minis, PC Engine, NeoGeo)
 *   PS1 Classic     PSISOIMG0000 (single disc) PGD at +0x400, PSTITLEIMG000000
 *                   (multi disc) PGD at +0x200; PGD MAC at +0x70 over [0, 0x70)
 * Before the key is returned the header is checked: a PGD by its DNAS-keyed MAC
 * at +0x80; an NPUMDIMG by re-verifying its MAC under the recovered key. The
 * NPUMDIMG check is only a consistency check (bbmac_getkey and Final2 are
 * inverses, so any 0xC0-byte header passes): NPUMDIMG carries no independent
 * authentication, and the EDAT MACs that the key is later used against are what
 * decide whether the key is right.
 * `kind` is the klicensee table row selector (NPUMDIMG byte +8, or 1 for PGD).
 * Nothing but the 16-byte key and its kind leaves this function. libkirk
 * state is thread-local in the pinned patched build. */

enum {
    NPDRM_OK = 0,
    NPDRM_UNRECOGNIZED = 1,
    NPDRM_SHORT = 2,
    NPDRM_UNSUPPORTED = 3,
    NPDRM_AUTHENTICATION = 4,
    NPDRM_KIRK = 5,
};

static const uint8_t dnas_key1a90[16] = {
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
    0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
};

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

/* 1 when the MAC of bytes[0, size) under `key` equals `expected`. */
static int verify_mac(int mac_type, const uint8_t *bytes, size_t size,
                      const uint8_t expected[16], const uint8_t key[16]) {
    MAC_KEY mac;
    int failed;
    failed = sceDrmBBMacInit(&mac, mac_type) ||
        sceDrmBBMacUpdate(&mac, (uint8_t *)bytes, (int)size) ||
        sceDrmBBMacFinal2(&mac, (uint8_t *)expected, (uint8_t *)key);
    memset(&mac, 0, sizeof(mac));
    return !failed;
}

static int version_key_of(int mac_type, const uint8_t *bytes, size_t size,
                          const uint8_t bbmac[16], uint8_t key[16]) {
    MAC_KEY mac;
    int failed;
    failed = sceDrmBBMacInit(&mac, mac_type) ||
        sceDrmBBMacUpdate(&mac, (uint8_t *)bytes, (int)size) ||
        bbmac_getkey(&mac, (uint8_t *)bbmac, key);
    memset(&mac, 0, sizeof(mac));
    return !failed;
}

int pspdb_npdrm_version_key(const uint8_t *psar, size_t size,
                            uint8_t version_key[16], uint8_t *kind) {
    uint8_t header[0xD0];
    uint8_t key[16];
    int result = NPDRM_UNRECOGNIZED;

    if (!psar || !version_key || !kind) return NPDRM_UNRECOGNIZED;
    kirk_init_prx();

    if (size >= 8 && memcmp(psar, "NPUMDIMG", 8) == 0) {
        if (size < 0xD0) return NPDRM_SHORT;
        memcpy(header, psar, sizeof(header));
        if (header[8] != 2 && header[8] != 3) {
            result = NPDRM_UNSUPPORTED;
            goto done;
        }
        if (!version_key_of(3, header, 0xC0, header + 0xC0, key)) {
            result = NPDRM_KIRK;
            goto done;
        }
        if (!verify_mac(3, header, 0xC0, header + 0xC0, key)) {
            result = NPDRM_AUTHENTICATION;
            goto done;
        }
        *kind = header[8];
    } else {
        size_t offset;
        int mac_type;
        if (size >= 12 && memcmp(psar, "PSISOIMG0000", 12) == 0) {
            offset = 0x400;
        } else if (size >= 16 && memcmp(psar, "PSTITLEIMG000000", 16) == 0) {
            offset = 0x200;
        } else {
            return NPDRM_UNRECOGNIZED;
        }
        if (size < offset + 0x90) return NPDRM_SHORT;
        memcpy(header, psar + offset, 0x90);
        if (memcmp(header, "\0PGD", 4) != 0) return NPDRM_UNRECOGNIZED;
        /* drm_type 1 selects MAC 1 (3 when key_index > 1), else MAC 2, exactly
         * as PSXtract and pgd_psx.c. MAC 2 is fuse-id bound and unavailable. */
        if (read_le32(header + 8) == 1) {
            mac_type = read_le32(header + 4) > 1 ? 3 : 1;
        } else {
            result = NPDRM_UNSUPPORTED;
            goto done;
        }
        if (!verify_mac(mac_type, header, 0x80, header + 0x80, dnas_key1a90)) {
            result = NPDRM_AUTHENTICATION;
            goto done;
        }
        if (!version_key_of(mac_type, header, 0x70, header + 0x70, key)) {
            result = NPDRM_KIRK;
            goto done;
        }
        *kind = 1;
    }
    memcpy(version_key, key, 16);
    result = NPDRM_OK;

done:
    memset(header, 0, sizeof(header));
    memset(key, 0, sizeof(key));
    return result;
}
