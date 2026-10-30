/* PSPDB native ATRAC3 arithmetic, GPL-3.0-or-later.
 * Mathematical translation of the original PSX ATRAC3 decoder.
 * Keep operation order and explicit binary32 stores: these are observable.
 */
#include <float.h>
#include <stdint.h>
#include <string.h>

_Static_assert(sizeof(float) == sizeof(uint32_t) && FLT_MANT_DIG == 24,
               "Sony IMLT requires IEEE binary32 float");
_Static_assert(LDBL_MANT_DIG == 64,
               "Sony IMLT requires x87 extended-precision long double");

static float sony_imlt_table_float(uint32_t bits)
{
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

/*
 * Translation of Sony RVA 0xc690..0xca06. Use the original round-to-nearest
 * x87 environment and compile without floating-point reassociation/fast-math.
 * Volatile binary32 destinations reproduce FSTP DWORD rounding even with
 * -fexcess-precision=fast; values retained on the x87 stack use long double.
 * Tables are the 128-dword captures at globals 0x12328..0x12348, in order.
 * The supplied window is the final 0xaff0 normalized window, not bare 0xae30.
 */
static void sony_imlt256(const float input[256], float output[512],
                  const float window[512], int odd,
                  const uint32_t tables[9][128])
{
    float data[256];
    volatile float real[128];
    volatile float imag[128];
    uint32_t visited[128] = {0};
    volatile float *const compact = data;
    volatile float *const pcm = output;

    /* 0xc690..0xc6db: bit-copy input, reversing only when odd == 1. */
    if (odd == 1) {
        for (unsigned i = 0; i < 256; ++i)
            memcpy(&data[i], &input[255 - i], sizeof(data[i]));
    } else {
        memcpy(data, input, sizeof(data));
    }

    /* 0xc6dd..0xc734: rotate the forward even-indexed input pairs. */
    for (unsigned i = 0; i < 64; ++i) {
        const float a = sony_imlt_table_float(tables[0][i]);
        const float b = sony_imlt_table_float(tables[1][i]);
        const long double first = data[4 * i];
        const long double second = data[4 * i + 2];
        real[i] = first * (long double)a - (long double)b * second;
        imag[i] = first * (long double)b + second * (long double)a;
    }

    /* 0xc736..0xc774: fold the backward odd-indexed input pairs. */
    for (unsigned j = 0; j < 64; ++j) {
        const unsigned i = 64 + j;
        const float a = sony_imlt_table_float(tables[0][i]);
        const float b = sony_imlt_table_float(tables[1][i]);
        const long double first = data[253 - 4 * j];
        const long double second = data[255 - 4 * j];
        real[i] = first * (long double)b - (long double)a * second;
        imag[i] = -(first * (long double)a) - (long double)b * second;
    }

    /* 0xc776..0xc7f1: the original visited-index permutation swaps. */
    for (unsigned i = 0; i < 128; ++i) {
        if (!visited[i]) {
            const uint32_t other = tables[8][i];
            const float saved_imag = imag[other];
            visited[other] = 1;
            const long double saved_real = real[other];
            real[other] = real[i];
            real[i] = saved_real;
            imag[other] = imag[i];
            imag[i] = saved_imag;
        }
    }

    /* 0xc7f3..0xc8cd: seven radix-2 stages, in the original group order. */
    for (unsigned half = 1, stride = 64; half < 128; half *= 2, stride /= 2) {
        for (unsigned base = 0; base < 128; base += 2 * half) {
            for (unsigned j = 0; j < half; ++j) {
                const unsigned lower = base + j;
                const unsigned upper = lower + half;
                const unsigned twiddle = j * stride;
                const float a = sony_imlt_table_float(tables[6][twiddle]);
                const float b = sony_imlt_table_float(tables[7][twiddle]);
                const long double rotated_real =
                    (long double)real[upper] * (long double)a
                    - (long double)b * (long double)imag[upper];
                /* 0xc85f stores only the imaginary rotation to binary32. */
                const volatile float rotated_imag =
                    (long double)b * (long double)real[upper]
                    + (long double)a * (long double)imag[upper];
                real[upper] = (long double)real[lower] - rotated_real;
                imag[upper] = (long double)imag[lower]
                              - (long double)rotated_imag;
                real[lower] = rotated_real + (long double)real[lower];
                imag[lower] = (long double)rotated_imag
                              + (long double)imag[lower];
            }
        }
    }

    /* 0xc8d3..0xc985: postrotate into the reused 256-float input area. */
    for (unsigned i = 0; i < 128; ++i) {
        const unsigned reverse = 127 - i;
        const float a = sony_imlt_table_float(tables[2][i]);
        const float b = sony_imlt_table_float(tables[3][i]);
        const float c = sony_imlt_table_float(tables[4][i]);
        const float d = sony_imlt_table_float(tables[5][i]);
        long double forward = (long double)b * (long double)real[reverse];
        forward += (long double)imag[reverse] * (long double)d;
        forward += (long double)real[i] * (long double)a;
        forward += (long double)imag[i] * (long double)c;
        compact[i] = forward;

        long double backward = (long double)real[i] * (long double)c;
        backward -= (long double)real[reverse] * (long double)d;
        backward -= (long double)imag[i] * (long double)a;
        backward += (long double)b * (long double)imag[reverse];
        compact[255 - i] = backward;
    }

    /* 0xc987..0xc9d5: first and last quarters, with final window stores. */
    for (unsigned i = 0; i < 128; ++i) {
        pcm[i] = (long double)window[i] * (long double)compact[128 + i];
        pcm[384 + i] = -((long double)window[384 + i]
                         * (long double)compact[i]);
    }

    /* 0xc9d7..0xca06: the middle half is negated and read backwards. */
    for (unsigned i = 0; i < 256; ++i)
        pcm[128 + i] = -((long double)window[128 + i]
                         * (long double)compact[255 - i]);
}
