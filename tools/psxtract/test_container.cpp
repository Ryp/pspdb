// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise real container readers using generated, sparse PSAR inputs.
#define main psxtract_cli_main
#include "psxtract.cpp"
#undef main
#include <unistd.h>
#include <sys/stat.h>

static void require(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "Container regression: %s\n", message);
        exit(1);
    }
}

static void enter_case(const char* name) {
    require(mkdir(name, 0700) == 0 && chdir(name) == 0, "cannot isolate case");
}

static void leave_case(FILE* source) {
    require(fclose(source) == 0, "cannot close source");
    require(chdir("..") == 0, "cannot leave case");
}

static void absent(const char* name) {
    require(access(name, F_OK) != 0, "published output for malformed input");
}

static const unsigned char payload[] = {0x89, 0x50, 0x4e, 0x47, 0x42};

static FILE* startdat_source(uint32_t offset, const STARTDAT_HEADER& header,
                            int64_t source_size, bool multidisc) {
    FILE* source = tmpfile();
    require(source != nullptr, "cannot create source");
    require(fseek(source, multidisc ? 0x10 : 0xC, SEEK_SET) == 0 &&
            fwrite(&offset, sizeof(offset), 1, source) == 1, "cannot write offset");
    if (offset) {
        require(_fseeki64(source, offset, SEEK_SET) == 0 &&
                fwrite(&header, sizeof(header), 1, source) == 1 &&
                fwrite(payload, 1, sizeof(payload), source) == sizeof(payload),
                "cannot write STARTDAT");
    }
    require(fflush(source) == 0 && ftruncate(fileno(source), source_size) == 0,
            "cannot set source boundary");
    return source;
}

static void check_bytes(const char* name, const void* bytes, size_t size) {
    FILE* file = fopen(name, "rb");
    require(file != nullptr, "missing output");
    unsigned char actual[sizeof(STARTDAT_HEADER) + sizeof(payload)];
    require(size <= sizeof(actual) && fread(actual, 1, sizeof(actual), file) == size &&
            memcmp(actual, bytes, size) == 0 && !ferror(file), "incorrect output bytes");
    require(fclose(file) == 0, "cannot close output");
}

static void check_startdat(const char* name, uint32_t offset, STARTDAT_HEADER header,
                          int64_t source_size, bool multidisc, int64_t expected) {
    enter_case(name);
    FILE* source = startdat_source(offset, header, source_size, multidisc);
    require(extract_startdat(source, multidisc) == expected, "incorrect STARTDAT result");
    if (expected > 0) {
        unsigned char bytes[sizeof(header) + sizeof(payload)];
        memcpy(bytes, &header, sizeof(header));
        memcpy(bytes + sizeof(header), payload, sizeof(payload));
        check_bytes("STARTDAT.BIN", bytes, sizeof(bytes));
        check_bytes("STARTDAT.PNG", payload, sizeof(payload));
    } else {
        absent("STARTDAT.BIN");
        absent("STARTDAT.PNG");
    }
    leave_case(source);
}

int main() {
    STARTDAT_HEADER header = {};
    memcpy(header.magic, "STARTDAT", sizeof(header.magic));
    header.header_size = sizeof(header);
    header.data_size = sizeof(payload);
    const int64_t end = 0x40 + sizeof(header) + sizeof(payload);
    check_startdat("single", 0x40, header, end, false, 0x40);
    check_startdat("multi", 0x40, header, end, true, 0x40);
    check_startdat("unsigned-offset", UINT32_MAX, header,
                   (int64_t)UINT32_MAX + sizeof(header) + sizeof(payload), false, UINT32_MAX);
    check_startdat("absent", 0, header, 0x10, false, 0);
    check_startdat("short-offset", 0, header, 0xF, false, -1);
    check_startdat("short-multi-offset", 0, header, 0x13, true, -1);
    check_startdat("offset-past-eof", UINT32_MAX, header, 0x40, false, -1);
    check_startdat("short-header", 0x40, header, 0x40 + sizeof(header) - 1, false, -1);
    check_startdat("short-payload", 0x40, header, end - 1, false, -1);
    STARTDAT_HEADER malformed = header;
    malformed.header_size = sizeof(header) - 1;
    check_startdat("undersized-header", 0x40, malformed, end, false, -1);
    malformed.header_size = UINT32_MAX;
    malformed.data_size = 2;
    check_startdat("size-wraparound", 0x40, malformed, end, false, -1);

    enter_case("output-open-failure");
    FILE* source = startdat_source(0x40, header, end, false);
    require(mkdir("STARTDAT.BIN", 0700) == 0, "cannot block output");
    require(extract_startdat(source, false) == -1, "ignored output open failure");
    absent("STARTDAT.PNG");
    leave_case(source);

    // /dev/full rejects buffered data at write or close, not necessarily at fopen.
    enter_case("output-flush-failure");
    source = startdat_source(0x40, header, end, false);
    require(symlink("/dev/full", "STARTDAT.BIN") == 0, "cannot create failing output");
    require(extract_startdat(source, false) == -1, "ignored output flush failure");
    absent("STARTDAT.PNG");
    leave_case(source);

    enter_case("auxiliary-boundaries");
    source = tmpfile();
    require(source != nullptr && ftruncate(fileno(source), 0x100) == 0, "cannot create auxiliary source");
    require(decrypt_special_data(source, 0x100, 0) == 0, "rejected absent special data");
    require(decrypt_special_data(source, 0x100, 0x101) == -1, "accepted special offset past EOF");
    require(decrypt_special_data(source, 0x100, 0x71) == -1, "accepted short special PGD header");
    require(decrypt_special_data(source, 0x200, 0x100) == -1, "accepted stale special source size");
    require(decrypt_special_data(source, (int64_t)INT_MAX + 0x100, 1) == -1,
            "narrowed oversized special span");
    require(decrypt_unknown_data(source, 0, 0) == 0, "rejected absent unknown data");
    require(decrypt_unknown_data(source, 0x80, 0) == -1, "skipped unknown data without STARTDAT");
    require(decrypt_unknown_data(source, 0x80, 0x70) == -1, "accepted reversed unknown span");
    require(decrypt_unknown_data(source, 0x71, 0x100) == -1, "accepted short unknown PGD header");
    require(decrypt_unknown_data(source, 0x100, 0x200) == -1, "accepted unknown span past EOF");
    require(decrypt_unknown_data(source, 1, (int64_t)UINT32_MAX) == -1,
            "narrowed unsigned STARTDAT boundary");
    require(decrypt_iso_header(source, 0, nullptr, 0) == -1, "accepted truncated ISO header");
    require(decrypt_iso_header(source, (int64_t)UINT32_MAX + ISO_HEADER_OFFSET, nullptr, 0) == -1,
            "accepted ISO header beyond unsigned offset range");
    require(decrypt_iso_map(source, 0, 0x8F, nullptr) == -1, "accepted short ISO map PGD header");
    require(decrypt_iso_map(source, 0x80, 0x90, nullptr) == -1, "accepted truncated ISO map");
    absent("SPECIAL_DATA.BIN");
    absent("SPECIAL_DATA.PNG");
    absent("UNKNOWN_DATA.BIN");
    absent("ISO_HEADER.BIN");
    absent("ISO_MAP.BIN");
    leave_case(source);
    puts("PSXtract container boundary regressions passed");
}
