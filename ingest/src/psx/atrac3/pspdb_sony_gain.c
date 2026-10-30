/* PSPDB native ATRAC3 arithmetic, GPL-3.0-or-later.
 * Mathematical translation of the original PSX ATRAC3 decoder.
 * Keep operation order and explicit binary32 stores: these are observable.
 */
#include <stdint.h>

/*
 * Native translation of Sony 0x67a4b0e0, with n fixed at 512.
 * Interpolated samples are independent 2^(weighted / 8) results rounded to
 * binary32 at a volatile float store, not a float recurrence. The original
 * translation used powl(2, weighted * 0.125L); weighted / 8 = q + r / 8 with
 * integer q, so the result is 2^q * (float)2^(r / 8). The eight (float)2^(r / 8)
 * constants below are correctly rounded (none lies within 0.06 ulp of a
 * rounding midpoint, so they equal powl's result) and make the decoder
 * independent of the C library's powl.
 *
 * Records are RAW Sony 64-byte arguments: count at word 0, locations at
 * words 1..7, level codes at words 8..14, and an unread word 15. Valid
 * records have count 0..7, locations 0..31 and level codes 0..15.
 * The source skips a point whose inclusive endpoint precedes its cursor.
 */
/* Bit patterns of (float)2^(r / 8), r = 0..7. */
static const uint32_t sony_pow2_eighths[8] = {
    0x3f800000u, 0x3f8b95c2u, 0x3f9837f0u, 0x3fa5fed7u,
    0x3fb504f3u, 0x3fc5672au, 0x3fd744fdu, 0x3feac0c7u,
};

/* (float)2^(weighted / 8) for |weighted| <= 176 (exponent stays normal). */
static float sony_pow2_weighted(int weighted)
{
    const int q = weighted >> 3; /* floor */
    const uint32_t bits = sony_pow2_eighths[weighted & 7] + ((uint32_t)q << 23);
    float value;
    __builtin_memcpy(&value, &bits, sizeof(value));
    return value;
}

static int sony_gain512(const int32_t first[16], const int32_t second[16],
                 float output[512])
{
    int32_t exponent[64] = {0};
    int cursor = 0;

    /* b10d-b133: second record assigns through location + 32, inclusive. */
    for (int point = 0; point < second[0]; ++point) {
        const int end = second[1 + point] + 32;
        const int32_t level = second[8 + point] - 4;
        while (cursor <= end)
            exponent[cursor++] = level;
    }

    /* b14b-b177: first record adds through its location, inclusive. */
    cursor = 0;
    for (int point = 0; point < first[0]; ++point) {
        const int end = first[1 + point];
        const int32_t level = first[8 + point] - 4;
        while (cursor <= end)
            exponent[cursor++] += level;
    }

    volatile float *const rounded_output = output;
    int previous = 0;
    int out = 511;

    /* b195 initializes the map pointer to e[63]; b254 decrements it. */
    for (int block = 63; block >= 0; --block) {
        const int target = -exponent[block];
        if (target == previous) {
            /* b1ac-b1ee: integer shift, optionally reciprocal, eight stores. */
            const long double factor = target < 0
                ? 1.0L / (int32_t)(UINT32_C(1) << -target)
                : (long double)(int32_t)(UINT32_C(1) << target);
            for (int sample = 0; sample < 8; ++sample)
                rounded_output[out--] = (float)factor;
        } else {
            /* b1f2-b248: exclude old endpoint, include new; write backward. */
            int old_term = 7 * previous;
            int new_term = target;
            for (int sample = 0; sample < 8; ++sample) {
                const int weighted = old_term + new_term;
                rounded_output[out--] = sony_pow2_weighted(weighted);
                new_term += target;
                old_term -= previous;
            }
        }
        previous = target;
    }
    return 0;
}
