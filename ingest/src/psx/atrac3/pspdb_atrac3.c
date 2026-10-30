/*
 * PSPDB native PSX ATRAC3 decoder, GPL-3.0-or-later (contains LGPL-2.1-or-later
 * FFmpeg code, see NOTICE).
 *
 * Derived from FFmpeg libavcodec/atrac3.c and atrac.c (commit
 * 59dd21047e86badeb1b142dff03f18acbbd074fa) with tools/patches/ffmpeg-atrac3-exact.patch
 * applied, trimmed to what PSX Classics audio needs: 2-channel SINGLE coding
 * mode (the transport's fixed 14-byte extradata selects it), 384-byte frames,
 * no libavutil/libavcodec dependency.
 *
 * Original FFmpeg copyright:
 *   Copyright (c) 2006-2008 Maxim Poliakovski
 *   Copyright (c) 2006-2008 Benjamin Larsson
 * This file is part of FFmpeg; FFmpeg is free software under the GNU Lesser
 * General Public License version 2.1 or later.
 *
 * Exactness: the decoder reproduces the Sony ACM decoder's x87 arithmetic.
 * `long double` and `volatile float` stores in this file and the pspdb_sony_*
 * sources are observable; do not reorder, contract or "simplify" them.
 */
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "pspdb_atrac3.h"

#if !defined(__x86_64__) && !defined(__i386__)
#error "Exact ATRAC3 requires x87 extended-precision long double"
#endif
_Static_assert(FLT_MANT_DIG == 24 && DBL_MANT_DIG == 53 && LDBL_MANT_DIG == 64,
               "Exact ATRAC3 requires IEEE float/double and x87 long double");

#define SAMPLES_PER_FRAME 1024
#define MDCT_SIZE 512
#define CHANNELS 2
#define BLOCK_ALIGN 384
#define UNIT_BYTES (BLOCK_ALIGN / CHANNELS)
#define ATRAC3_VLC_BITS 8
#define FRAME_ERR (-1)

typedef struct AtracGainInfo {
    int num_points;
    int lev_code[7];
    int loc_code[7];
} AtracGainInfo;

#include "atrac3data.h"
#include "pspdb_atrac3_tables.h"

static float pspdb_f32(uint32_t bits)
{
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static const int sony_max_quant[8] = {0, 1, 2, 3, 4, 7, 15, 31};

typedef struct GainBlock {
    AtracGainInfo g_block[4];
} GainBlock;

typedef struct TonalComponent {
    int pos;
    int num_coefs;
    int coef[8];
    float scale_factor;
    int max_quant;
} TonalComponent;

typedef struct ChannelUnit {
    int bands_coded;
    int num_components;
    float prev_frame[SAMPLES_PER_FRAME];
    int gc_blk_switch;
    TonalComponent components[64];
    GainBlock gain_block[2];
    float spectrum[SAMPLES_PER_FRAME];
    float imdct_buf[SAMPLES_PER_FRAME];
    float delay_buf1[46];
    float delay_buf2[46];
    float delay_buf3[46];
} ChannelUnit;

/* 256-entry single-level VLC tables (all ATRAC3 codes are <= 8 bits). */
typedef struct VlcEntry {
    int8_t sym;
    uint8_t len;
} VlcEntry;

typedef VlcEntry VlcTables[7][1 << ATRAC3_VLC_BITS];

typedef struct Decoder {
    ChannelUnit units[CHANNELS];
    float temp_buf[1070];
    VlcTables vlc;
} Decoder;

/* Bounded MSB-first bit reader; reads past the end return zero bits. */
typedef struct Bits {
    const uint8_t *buf;
    size_t size_bits;
    size_t pos;
    const VlcTables *vlc;
} Bits;

static unsigned get_bits(Bits *b, int n)
{
    unsigned v = 0;
    for (int i = 0; i < n; i++, b->pos++) {
        unsigned bit = 0;
        if (b->pos < b->size_bits)
            bit = (b->buf[b->pos >> 3] >> (7 - (b->pos & 7))) & 1;
        v = (v << 1) | bit;
    }
    return v;
}

static int get_sbits(Bits *b, int n)
{
    unsigned v = get_bits(b, n);
    return (int)(v << (32 - n)) >> (32 - n);
}

static void build_vlc_tables(VlcTables vlc)
{
    const uint8_t (*tab)[2] = atrac3_hufftabs;
    for (int t = 0; t < 7; t++) {
        uint32_t code = 0;
        for (int i = 0; i < huff_tab_sizes[t]; i++) {
            unsigned len = tab[i][1];
            int sym = tab[i][0] - 31;
            unsigned first = code >> (32 - ATRAC3_VLC_BITS);
            unsigned count = 1u << (ATRAC3_VLC_BITS - len);
            for (unsigned k = 0; k < count; k++) {
                vlc[t][first + k].sym = (int8_t)sym;
                vlc[t][first + k].len = (uint8_t)len;
            }
            code += 1u << (32 - len);
        }
        tab += huff_tab_sizes[t];
    }
}

static int get_vlc(Bits *b, int table)
{
    unsigned idx = 0;
    for (int i = 0; i < ATRAC3_VLC_BITS; i++) {
        unsigned bit = 0;
        size_t p = b->pos + i;
        if (p < b->size_bits)
            bit = (b->buf[p >> 3] >> (7 - (p & 7))) & 1;
        idx = (idx << 1) | bit;
    }
    b->pos += (*b->vlc)[table][idx].len;
    return (*b->vlc)[table][idx].sym;
}

#include "pspdb_sony_imlt.c"
#include "pspdb_sony_tables.h"
#include "pspdb_sony_gain.c"

static void pspdb_apply_sony_gain(const float *input, float *previous,
                                  const AtracGainInfo *current, const AtracGainInfo *next,
                                  float *output)
{
    int32_t first[16] = {0}, second[16] = {0};
    float factors[512];
    first[0] = current->num_points;
    second[0] = next->num_points;
    for (int i = 0; i < first[0]; ++i) {
        first[1 + i] = current->loc_code[i];
        first[8 + i] = current->lev_code[i];
    }
    for (int i = 0; i < second[0]; ++i) {
        second[1 + i] = next->loc_code[i];
        second[8 + i] = next->lev_code[i];
    }
    sony_gain512(first, second, factors);
    /* Sony 0x48370: store pre-scaled upper overlap, add lower in x87 precision. */
    for (unsigned i = 0; i < 256; ++i) {
        ((volatile float *)output)[i] = (long double)input[i] * factors[i] + previous[i];
        ((volatile float *)previous)[i] = (long double)input[256 + i] * factors[256 + i];
    }
}

/* Regular 512 points IMDCT without overlapping. */
static void imlt(float *input, float *output, int odd_band)
{
    sony_imlt256(input, output, pspdb_unity_window, odd_band, pspdb_sony_tables);
    for (int i = 0; i < MDCT_SIZE; ++i)
        output[i] *= -0x1p-15f;
    /* Windowing (ff_float_dsp vector_fmul). */
    for (int i = 0; i < MDCT_SIZE; ++i)
        output[i] = output[i] * pspdb_f32(pspdb_mdct_window_bits[i]);
}

static void read_quant_spectral_coeffs(Bits *gb, int selector, int coding_flag,
                                       int *mantissas, int num_codes)
{
    int i, code, huff_symb;

    if (selector == 1)
        num_codes /= 2;

    if (coding_flag != 0) {
        int num_bits = clc_length_tab[selector];

        if (selector > 1) {
            for (i = 0; i < num_codes; i++) {
                if (num_bits)
                    code = get_sbits(gb, num_bits);
                else
                    code = 0;
                mantissas[i] = code;
            }
        } else {
            for (i = 0; i < num_codes; i++) {
                if (num_bits)
                    code = get_bits(gb, num_bits);
                else
                    code = 0;
                mantissas[i * 2    ] = mantissa_clc_tab[code >> 2];
                mantissas[i * 2 + 1] = mantissa_clc_tab[code &  3];
            }
        }
    } else {
        if (selector != 1) {
            for (i = 0; i < num_codes; i++)
                mantissas[i] = get_vlc(gb, selector - 1);
        } else {
            for (i = 0; i < num_codes; i++) {
                huff_symb = get_vlc(gb, selector - 1);
                mantissas[i * 2    ] = mantissa_vlc_tab[huff_symb * 2    ];
                mantissas[i * 2 + 1] = mantissa_vlc_tab[huff_symb * 2 + 1];
            }
        }
    }
}

static int decode_spectrum(Bits *gb, float *output)
{
    int num_subbands, coding_mode, i, j, first, last, subband_size;
    int subband_vlc_index[32], sf_index[32];
    int mantissas[128];
    volatile float scale_factor;

    num_subbands = get_bits(gb, 5);
    coding_mode  = get_bits(gb, 1);

    for (i = 0; i <= num_subbands; i++)
        subband_vlc_index[i] = get_bits(gb, 3);

    for (i = 0; i <= num_subbands; i++) {
        if (subband_vlc_index[i] != 0)
            sf_index[i] = get_bits(gb, 6);
    }

    for (i = 0; i <= num_subbands; i++) {
        first = subband_tab[i    ];
        last  = subband_tab[i + 1];

        subband_size = last - first;

        if (subband_vlc_index[i] != 0) {
            read_quant_spectral_coeffs(gb, subband_vlc_index[i], coding_mode,
                                       mantissas, subband_size);

            /* Sony 0x4905f..0x49083 rounds the division before multiplication. */
            scale_factor = (long double)pspdb_f32(pspdb_sf_table_bits[sf_index[i]]) /
                           (sony_max_quant[subband_vlc_index[i]] + 0.5L);

            for (j = 0; first < last; first++, j++)
                ((volatile float *)output)[first] = (long double)mantissas[j] * scale_factor;
        } else {
            memset(output + first, 0, subband_size * sizeof(*output));
        }
    }

    first = subband_tab[i];
    memset(output + first, 0, (SAMPLES_PER_FRAME - first) * sizeof(*output));
    return num_subbands;
}

static int decode_tonal_components(Bits *gb, TonalComponent *components, int num_bands)
{
    int i, b, c, m;
    int nb_components, coding_mode_selector, coding_mode;
    int band_flags[4], mantissa[8];
    int component_count = 0;

    nb_components = get_bits(gb, 5);

    if (nb_components == 0)
        return 0;

    coding_mode_selector = get_bits(gb, 2);
    if (coding_mode_selector == 2)
        return FRAME_ERR;

    coding_mode = coding_mode_selector & 1;

    for (i = 0; i < nb_components; i++) {
        int coded_values_per_component, quant_step_index;

        for (b = 0; b <= num_bands; b++)
            band_flags[b] = get_bits(gb, 1);

        coded_values_per_component = get_bits(gb, 3);

        quant_step_index = get_bits(gb, 3);
        if (quant_step_index <= 1)
            return FRAME_ERR;

        if (coding_mode_selector == 3)
            coding_mode = get_bits(gb, 1);

        for (b = 0; b < (num_bands + 1) * 4; b++) {
            int coded_components;

            if (band_flags[b >> 2] == 0)
                continue;

            coded_components = get_bits(gb, 3);

            for (c = 0; c < coded_components; c++) {
                TonalComponent *cmp = &components[component_count];
                int sf_index, coded_values, max_coded_values;

                sf_index = get_bits(gb, 6);
                if (component_count >= 64)
                    return FRAME_ERR;

                cmp->pos = b * 64 + get_bits(gb, 6);

                max_coded_values = SAMPLES_PER_FRAME - cmp->pos;
                coded_values     = coded_values_per_component + 1;
                coded_values     = coded_values < max_coded_values ? coded_values : max_coded_values;

                cmp->scale_factor = pspdb_f32(pspdb_sf_table_bits[sf_index]);
                cmp->max_quant = sony_max_quant[quant_step_index];

                read_quant_spectral_coeffs(gb, quant_step_index, coding_mode,
                                           mantissa, coded_values);

                cmp->num_coefs = coded_values;

                /* Keep mantissas until Sony's extended-precision tonal addition. */
                for (m = 0; m < coded_values; m++)
                    cmp->coef[m] = mantissa[m];

                component_count++;
            }
        }
    }

    return component_count;
}

static int decode_gain_control(Bits *gb, GainBlock *block, int num_bands)
{
    int b, j;
    int *level, *loc;

    AtracGainInfo *gain = block->g_block;

    for (b = 0; b <= num_bands; b++) {
        gain[b].num_points = get_bits(gb, 3);
        level              = gain[b].lev_code;
        loc                = gain[b].loc_code;

        for (j = 0; j < gain[b].num_points; j++) {
            level[j] = get_bits(gb, 4);
            loc[j]   = get_bits(gb, 5);
            if (j && loc[j] <= loc[j - 1])
                return FRAME_ERR;
        }
    }

    for (; b < 4 ; b++)
        gain[b].num_points = 0;

    return 0;
}

static int add_tonal_components(float *spectrum, int num_components, TonalComponent *components)
{
    int i, j, last_pos = -1;
    int *input;
    volatile float *output;

    for (i = 0; i < num_components; i++) {
        int end = components[i].pos + components[i].num_coefs;
        last_pos = end > last_pos ? end : last_pos;
        input    = components[i].coef;
        output   = &spectrum[components[i].pos];

        for (j = 0; j < components[i].num_coefs; j++)
            /* Sony 0x491a7..0x491c5 rounds only after adding to the spectrum. */
            output[j] = (long double)input[j] * components[i].scale_factor /
                        (components[i].max_quant + 0.5L) + output[j];
    }

    return last_pos;
}

static int decode_channel_sound_unit(ChannelUnit *snd, Bits *gb, float *output)
{
    int band, ret, num_subbands, last_tonal, num_bands;
    GainBlock *gain1 = &snd->gain_block[    snd->gc_blk_switch];
    GainBlock *gain2 = &snd->gain_block[1 - snd->gc_blk_switch];

    if (get_bits(gb, 6) != 0x28)
        return FRAME_ERR;

    snd->bands_coded = get_bits(gb, 2);

    ret = decode_gain_control(gb, gain2, snd->bands_coded);
    if (ret)
        return ret;

    snd->num_components = decode_tonal_components(gb, snd->components, snd->bands_coded);
    if (snd->num_components < 0)
        return snd->num_components;

    num_subbands = decode_spectrum(gb, snd->spectrum);

    last_tonal = add_tonal_components(snd->spectrum, snd->num_components, snd->components);

    num_bands = (subband_tab[num_subbands + 1] - 1) >> 8;
    if (last_tonal >= 0) {
        int tonal_bands = (last_tonal + 256) >> 8;
        num_bands = tonal_bands > num_bands ? tonal_bands : num_bands;
    }

    for (band = 0; band < 4; band++) {
        if (band <= num_bands)
            imlt(&snd->spectrum[band * 256], snd->imdct_buf, band & 1);
        else
            memset(snd->imdct_buf, 0, 512 * sizeof(*snd->imdct_buf));

        pspdb_apply_sony_gain(snd->imdct_buf, &snd->prev_frame[band * 256],
                              &gain1->g_block[band], &gain2->g_block[band],
                              &output[band * 256]);
    }

    snd->gc_blk_switch ^= 1;

    return 0;
}

#include "pspdb_qmf_coefficients.h"

/* ff_atrac_iqmf with Sony's extended-precision accumulation order. */
static void atrac_iqmf(float *inlo, float *inhi, unsigned int nIn, float *pOut,
                       float *delayBuf, float *temp)
{
    int i, j;
    float *p1, *p3;

    memcpy(temp, delayBuf, 46 * sizeof(float));

    p3 = temp + 46;

    for (i = 0; i < (int)nIn; i += 2) {
        p3[2*i+0] = inlo[i  ] + inhi[i  ];
        p3[2*i+1] = inlo[i  ] - inhi[i  ];
        p3[2*i+2] = inlo[i+1] + inhi[i+1];
        p3[2*i+3] = inlo[i+1] - inhi[i+1];
    }

    p1 = temp;
    for (j = nIn; j != 0; j--) {
        long double s1 = (long double)p1[46] * sony_qmf_window[46];
        long double s2 = (long double)p1[47] * sony_qmf_window[47];

        for (i = 44; i >= 0; i -= 2) {
            s1 += (long double)p1[i] * sony_qmf_window[i];
            s2 += (long double)p1[i+1] * sony_qmf_window[i+1];
        }

        pOut[0] = s2;
        pOut[1] = s1;

        p1 += 2;
        pOut += 2;
    }

    memcpy(delayBuf, temp + nIn * 2, 46 * sizeof(float));
}

static int decode_frame(Decoder *d, const uint8_t *databuf, float out[CHANNELS][SAMPLES_PER_FRAME])
{
    for (int i = 0; i < CHANNELS; i++) {
        Bits gb = { databuf + i * UNIT_BYTES, UNIT_BYTES * 8, 0, &d->vlc };
        int ret = decode_channel_sound_unit(&d->units[i], &gb, out[i]);
        if (ret != 0)
            return ret;
    }

    for (int i = 0; i < CHANNELS; i++) {
        float *p1 = out[i];
        float *p2 = p1 + 256;
        float *p3 = p2 + 256;
        float *p4 = p3 + 256;
        atrac_iqmf(p1, p2, 256, p1, d->units[i].delay_buf1, d->temp_buf);
        atrac_iqmf(p4, p3, 256, p3, d->units[i].delay_buf2, d->temp_buf);
        atrac_iqmf(p1, p3, 512, p1, d->units[i].delay_buf3, d->temp_buf);
    }
    return 0;
}

size_t pspdb_atrac3_pcm_size(size_t nframes)
{
    size_t samples = nframes * SAMPLES_PER_FRAME;
    if (nframes > SIZE_MAX / SAMPLES_PER_FRAME / 4 || samples <= PSPDB_ATRAC3_PRIMING_SAMPLES)
        return 0;
    return (samples - PSPDB_ATRAC3_PRIMING_SAMPLES) * 4;
}

static int arithmetic_ok(void)
{
    unsigned short control;
    __asm__ __volatile__("fnstcw %0" : "=m" (control));
    /* Extended precision, round to nearest. */
    return (control & 0x0f00) == 0x0300;
}

int pspdb_atrac3_decode(const uint8_t *frames, size_t nframes, uint8_t *pcm, size_t pcm_capacity)
{
    if (!arithmetic_ok())
        return PSPDB_ATRAC3_BAD_ARITHMETIC;
    size_t pcm_size = pspdb_atrac3_pcm_size(nframes);
    if (!pcm_size || pcm_size != pcm_capacity)
        return PSPDB_ATRAC3_BAD_SIZE;
    Decoder *d = calloc(1, sizeof(*d));
    if (!d)
        return PSPDB_ATRAC3_BAD_STREAM;
    build_vlc_tables(d->vlc);
    float out[CHANNELS][SAMPLES_PER_FRAME];
    size_t skip = PSPDB_ATRAC3_PRIMING_SAMPLES;
    size_t written = 0;
    int status = PSPDB_ATRAC3_OK;

    for (size_t f = 0; f < nframes; f++) {
        if (decode_frame(d, frames + f * BLOCK_ALIGN, out) != 0) {
            status = PSPDB_ATRAC3_BAD_STREAM;
            break;
        }
        for (int i = 0; i < SAMPLES_PER_FRAME; i++) {
            if (skip > 0) {
                skip--;
                continue;
            }
            for (int ch = 0; ch < CHANNELS; ch++) {
                float value = -out[ch][i] * 32768.0f;
                int sample = value < -32768 ? -32768 : value > 32767 ? 32767
                           : value != value ? 0 : (int)value;
                pcm[written++] = sample & 255;
                pcm[written++] = (sample >> 8) & 255;
            }
        }
    }
    free(d);
    if (status == PSPDB_ATRAC3_OK && written != pcm_size)
        return PSPDB_ATRAC3_BAD_SIZE;
    return status;
}
