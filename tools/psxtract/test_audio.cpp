// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise native extraction and reconstruction without game fixtures or decoding.
#define main psxtract_cli_main
#include "psxtract.cpp"
#undef main
#include <unistd.h>
#include <sys/stat.h>

static void require(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "Audio regression: %s\n", message);
        exit(1);
    }
}

static void put(FILE* file, long offset, const void* data, size_t size) {
    require(fseek(file, offset, SEEK_SET) == 0, "cannot seek generated input");
    require(fwrite(data, 1, size, file) == size && fflush(file) == 0, "cannot write generated input");
}

static void enter(const char* name) {
    require(mkdir(name, 0700) == 0 && chdir(name) == 0, "cannot isolate case");
}

static void leave() {
    require(chdir("..") == 0, "cannot leave case");
}

static void check_cue_boundaries() {
    FILE* table = tmpfile();
    require(table != nullptr, "cannot create CUE table");
    CUE_ENTRY entry = {};
    entry.type = 1;
    entry.I1s = 3;
    put(table, CUE_LEADOUT_OFFSET, &entry, sizeof(entry));
    entry.I1s = 2;
    put(table, 0x428, &entry, sizeof(entry));
    // Missing next entry must not masquerade as the last-track sentinel.
    require(get_track_size_from_cue(table, 0x428) < 0, "missing next CUE record accepted");
    entry.I1s = 4;
    put(table, CUE_LEADOUT_OFFSET, &entry, sizeof(entry));
    entry.I1s = 5;
    put(table, 0x41E + 98 * sizeof(entry), &entry, sizeof(entry));
    // Track 99 legitimately reaches the CDDA table boundary, without a next CUE.
    require(get_track_size_from_cue(table, 0x41E + 98 * sizeof(entry)) == 75,
            "last supported CUE track rejected");
    require(fclose(table) == 0, "cannot close CUE table");
}

static void check_audio_source(const char* name, bool short_table, bool short_payload, bool overrange) {
    enter(name);
    FILE* psar = tmpfile();
    FILE* table = tmpfile();
    require(psar && table, "cannot create extraction inputs");
    // With checksum zero, only the final word is nonzero, so this single
    // unscrambled chunk has these same known bytes. Extra lookahead is not output.
    unsigned char source[2 * NBYTES] = {};
    memcpy(source + NBYTES - 4, "\x12\x34\x56\x78", 4);
    memset(source + NBYTES, 0xa5, NBYTES);
    put(psar, 1, source, sizeof(source) - (short_payload ? 1 : 0));
    CUE_ENTRY cue = {};
    cue.type = 1;
    cue.I1s = 1;
    put(table, CUE_LEADOUT_OFFSET, &cue, sizeof(cue));
    cue.I1s = 2;
    put(table, 0x428, &cue, sizeof(cue));
    CDDA_ENTRY entries[2] = {};
    entries[0].offset = 1;
    entries[0].size = overrange ? UINT32_MAX : NBYTES;
    if (short_table) {
        // A short zero record used to report success with no audio tracks.
        put(table, 0x800, &entries[1], sizeof(CDDA_ENTRY) - 1);
    } else {
        put(table, 0x800, entries, sizeof(entries));
    }
    int result = build_audio_at3(psar, table, 0, nullptr, 0, nullptr);
    require(fclose(psar) == 0 && fclose(table) == 0, "cannot close extraction inputs");
    if (short_table || short_payload || overrange) {
        require(result < 0, "incomplete or overrange source reported successful extraction");
        require(access("D00_TRACK02.AT3", F_OK) != 0, "published audio from incomplete source");
    } else {
        require(result == 1, "complete audio source rejected");
        FILE* output = fopen("D00_TRACK02.AT3", "rb");
        require(output != nullptr, "missing extracted audio");
        AT3_HEADER header;
        require(fread(&header, sizeof(header), 1, output) == 1, "missing extracted header");
        require(header.fact_param1 == 75 * SECTOR_SIZE / 4 && header.data_size == NBYTES,
                "wrong extracted audio length");
        unsigned char actual[NBYTES];
        require(fread(actual, 1, sizeof(actual), output) == sizeof(actual) &&
                memcmp(actual, source, sizeof(actual)) == 0, "changed extracted audio bytes");
        require(fgetc(output) == EOF && !ferror(output), "extra extracted audio bytes");
        require(fclose(output) == 0, "cannot close extracted audio");
    }
    leave();
}

static void check_wav_source(const char* name, bool short_at3, bool short_header, bool short_pcm) {
    enter(name);
    AT3_HEADER at3 = {};
    at3.fact_param1 = 3 * SECTOR_SIZE / 4;
    FILE* file = fopen("D00_TRACK02.AT3", "wb");
    require(file != nullptr, "cannot create AT3 header");
    put(file, 0, &at3, sizeof(at3) - (short_at3 ? 1 : 0));
    require(fclose(file) == 0, "cannot close AT3 header");
    unsigned char wave[50] = {};
    memcpy(wave, "RIFF", 4);
    wave[4] = sizeof(wave); // Native transport's deliberately noncanonical RIFF length.
    memcpy(wave + 8, "WAVEfmt ", 8);
    wave[16] = 18;
    wave[20] = 1;
    wave[22] = 2;
    memcpy(wave + 38, "data", 4);
    wave[42] = 4;
    wave[46] = 0x12;
    wave[47] = 0x34;
    wave[48] = 0x56;
    wave[49] = 0x78;
    file = fopen("D00_TRACK02.WAV", "wb");
    require(file != nullptr, "cannot create WAV input");
    put(file, 0, wave, short_header ? 45 : sizeof(wave) - (short_pcm ? 1 : 0));
    require(fclose(file) == 0, "cannot close WAV input");
    int result = convert_wav_to_bin(2, 0, 1, nullptr);
    if (short_at3 || short_header || short_pcm) {
        require(result < 0, "truncated derivative reported successful BIN reconstruction");
        require(access("D00_TRACK02.BIN", F_OK) != 0, "published BIN from truncated derivative");
    } else {
        require(result == 1, "complete WAV rejected");
        file = fopen("D00_TRACK02.BIN", "rb");
        require(file != nullptr, "missing reconstructed BIN");
        // Preserve the upstream offset44 read, including two header bytes, and padding.
        for (int i = 0; i < 3 * SECTOR_SIZE; ++i) {
            int expected = i >= SECTOR_SIZE && i < SECTOR_SIZE + 6 ? wave[44 + i - SECTOR_SIZE] : 0;
            require(fgetc(file) == expected, "changed reconstructed BIN bytes");
        }
        require(fgetc(file) == EOF && !ferror(file), "wrong reconstructed BIN length");
        require(fclose(file) == 0, "cannot close reconstructed BIN");
    }
    leave();
}

int main() {
    check_cue_boundaries();
    check_audio_source("complete-audio", false, false, false);
    check_audio_source("short-audio-table", true, false, false);
    check_audio_source("short-audio-payload", false, true, false);
    check_audio_source("oversized-audio", false, false, true);
    check_wav_source("complete-wave", false, false, false);
    check_wav_source("short-at3-header", true, false, false);
    check_wav_source("short-wave-header", false, true, false);
    check_wav_source("short-wave-pcm", false, false, true);
    puts("PSXtract audio boundary regressions passed");
}
