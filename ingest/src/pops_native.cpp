#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "PrxDecrypter.h"

extern "C" {
#include "libkirk/kirk_engine.h"
#include "libkirk/amctrl.h"
}

static uint32_t read_le32(const uint8_t *bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
        (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}

// Zig owns output, which must not overlap either input. Only the declared PRX
// envelope is used as reconstruction workspace; the whole DATA.BIN is borrowed.
extern "C" int pspdb_pops_decode(const uint8_t *psp, size_t psp_len,
                                const uint8_t *data_bin, size_t data_bin_len,
                                uint8_t *output, size_t output_len) {
    if (!psp || !output || psp_len < 0x150 || psp_len > INT_MAX ||
        std::memcmp(psp, "~PSP", 4) != 0 || psp[0x7c] != 20 ||
        read_le32(psp + 0xd0) != 0x0daa06f0) {
        return -10;
    }
    const size_t declared = read_le32(psp + 0x2c);
    const size_t compressed = read_le32(psp + 0xb0);
    const size_t offset = read_le32(psp + 0xb4);
    if (declared < 0x150 || declared > psp_len || output_len < declared ||
        compressed == 0 || compressed > INT_MAX || offset > declared - 0xd0 ||
        ((compressed + 15) & ~size_t(15)) > declared - 0xd0 - offset) {
        return -11;
    }

    size_t pgd_offset;
    if (data_bin && data_bin_len >= 12 && std::memcmp(data_bin, "PSISOIMG0000", 12) == 0) {
        pgd_offset = 0x400;
    } else if (data_bin && data_bin_len >= 13 && std::memcmp(data_bin, "PSTITLEIMG0000", 13) == 0) {
        pgd_offset = 0x200;
    } else {
        return -12;
    }
    if (pgd_offset > data_bin_len || data_bin_len - pgd_offset < 0x90) return -13;
    uint8_t pgd[0x90];
    std::memcpy(pgd, data_bin + pgd_offset, sizeof(pgd));
    if (std::memcmp(pgd, "\0PGD", 4) != 0) return -14;
    // This existing profile uses fixed keys only; fuse-bound profiles are rejected.
    if (read_le32(pgd + 4) != 1 || read_le32(pgd + 8) != 1) return -15;

    uint8_t dnas[16] = {
        0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
        0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
    };
    uint8_t seed[16];
    MAC_KEY mac;
    kirk_init_prx();
    if (sceDrmBBMacInit(&mac, 1) || sceDrmBBMacUpdate(&mac, pgd, 0x80) ||
        sceDrmBBMacFinal2(&mac, pgd + 0x80, dnas)) {
        return -16;
    }
    if (sceDrmBBMacInit(&mac, 1) || sceDrmBBMacUpdate(&mac, pgd, 0x70) ||
        bbmac_getkey(&mac, pgd + 0x70, seed)) {
        return -17;
    }

    // The pinned POPS recipe requires the title seed and type 5: header SHA1
    // and KIRK CMD1 CMAC both authenticate, with no weaker type fallback.
    const int result = pspDecryptPRX(psp, output, uint32_t(declared), seed, false);
    if (result < 0) return -18;
    if (size_t(result) != compressed) return -19;
    return result;
}
