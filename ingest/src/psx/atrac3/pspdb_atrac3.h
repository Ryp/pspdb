/* PSPDB native PSX ATRAC3 decoder entry point. */
#ifndef PSPDB_ATRAC3_H
#define PSPDB_ATRAC3_H

#include <stddef.h>
#include <stdint.h>

enum {
    PSPDB_ATRAC3_OK = 0,
    PSPDB_ATRAC3_BAD_ARITHMETIC = -1, /* x87 not in extended precision / round-to-nearest */
    PSPDB_ATRAC3_BAD_STREAM = -2,     /* undecodable ATRAC3 frame */
    PSPDB_ATRAC3_BAD_SIZE = -3,       /* frame count / output capacity mismatch */
};

/* Number of PCM samples (per channel) the PSX transport discards at the start. */
#define PSPDB_ATRAC3_PRIMING_SAMPLES 1165

/* PCM bytes produced for `nframes` 384-byte frames; 0 if nframes is too small. */
size_t pspdb_atrac3_pcm_size(size_t nframes);

/*
 * Decode `nframes` 384-byte stereo ATRAC3 frames (PSX Classics CDDA payload,
 * already unscrambled) to interleaved little-endian s16 stereo, skipping the
 * 1165 priming samples, sample = trunc(clamp(-float * 32768)).
 * `pcm_capacity` must equal pspdb_atrac3_pcm_size(nframes). Thread-safe.
 */
int pspdb_atrac3_decode(const uint8_t *frames, size_t nframes, uint8_t *pcm, size_t pcm_capacity);

#endif
