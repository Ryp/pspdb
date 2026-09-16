#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "PrxDecrypter.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The upstream KIRK command headers require a little-endian host"
#endif

// The output is also upstream's reconstruction workspace and must hold input_len
// bytes. Input and output must not overlap. Zig owns both allocation and errors.
extern "C" int pspdb_prx_decode(const uint8_t *input, size_t input_len,
                               uint8_t *output, size_t output_len) {
    if (input_len < sizeof(PSP_Header) || input_len > INT_MAX ||
        output_len < input_len || !input || !output ||
        (std::memcmp(input, "~PSP", 4) != 0 &&
         std::memcmp(input, "PSPsysGP", 8) != 0)) {
        return -1;
    }
    const uint32_t expected = uint32_t(input[0xb0]) |
        (uint32_t(input[0xb1]) << 8) | (uint32_t(input[0xb2]) << 16) |
        (uint32_t(input[0xb3]) << 24);
    if (expected == 0 || expected > input_len) return -2;

    // Known recipes fail terminally; KIRK checks CMAC or both type-6 ECDSA
    // signatures before releasing plaintext. Separate external PRX signatures
    // are not verified; there is no unauthenticated payload-only fallback.
    const int result = pspDecryptPRX(input, output, uint32_t(input_len), nullptr, false);
    // A matched PRX header followed by failed KIRK integrity is terminal,
    // including across Zig's optional console-signcheck normalization.
    if (result == -4) return -5;
    if (result < 0) return -3;
    if (uint32_t(result) != expected) return -4;
    return result;
}
