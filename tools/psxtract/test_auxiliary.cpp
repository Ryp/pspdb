// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the real extraction function without entering the PBP command line.
#define main psxtract_cli_main
#include "psxtract.cpp"
#undef main
#include <unistd.h>
#include <sys/stat.h>

static void require(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "Auxiliary regression: %s\n", message);
        exit(1);
    }
}

static void check_file(const char* path, const unsigned char* bytes, size_t size) {
    FILE* file = fopen(path, "rb");
    require(file != nullptr, "missing auxiliary output");
    unsigned char actual[ISO_BLOCK_SIZE];
    require(fread(actual, 1, sizeof(actual), file) == size, "wrong auxiliary size");
    require(memcmp(actual, bytes, size) == 0, "wrong auxiliary bytes");
    require(fgetc(file) == EOF && !ferror(file), "extra auxiliary bytes");
    require(fclose(file) == 0, "cannot close auxiliary output");
}

static void check_block(const char* directory, unsigned char* block, size_t prefix, bool valid) {
    require(mkdir(directory, 0700) == 0 && chdir(directory) == 0, "cannot isolate case");
    FILE* psar = tmpfile();
    FILE* table = tmpfile();
    require(psar && table, "cannot create input files");
    require(fseek(psar, 0x100000, SEEK_SET) == 0, "cannot seek input");
    require(fwrite(block, ISO_BLOCK_SIZE, 1, psar) == 1, "cannot write input block");
    require(fseek(table, 0x3c00, SEEK_SET) == 0, "cannot seek table");
    ISO_ENTRY entry = {};
    entry.size = ISO_BLOCK_SIZE;
    require(fwrite(&entry, sizeof(entry), 1, table) == 1, "cannot write table entry");
    entry.size = 0;
    require(fwrite(&entry, sizeof(entry), 1, table) == 1, "cannot terminate table");
    require(fflush(psar) == 0 && fflush(table) == 0, "cannot flush inputs");
    const int result = build_data_track(psar, table, 0, 0);
    require(fclose(psar) == 0 && fclose(table) == 0, "cannot close inputs");
    require((result == 0) == valid, "wrong extraction result");
    if (valid) {
        check_file("OVERDUMP.BIN", block + prefix, ISO_BLOCK_SIZE - prefix);
        if (prefix) check_file("TRASH.BIN", block, prefix);
        else require(access("TRASH.BIN", F_OK) != 0, "unexpected trash output");
    } else {
        require(access("TRASH.BIN", F_OK) != 0, "published unterminated trash");
        check_file("OVERDUMP.BIN", block, 0);
    }
    require(chdir("..") == 0, "cannot leave case");
}

int main() {
    unsigned char block[ISO_BLOCK_SIZE] = {};
    check_block("immediate-zero", block, 0, true);
    // A CD sync prefix must not skip a sector: the release scans from byte zero.
    block[1] = block[2] = block[3] = 0xff;
    memset(block + 4, 0x33, 4);
    check_block("sync-prefix", block, 8, true);
    memset(block, 0x33, sizeof(block));
    memset(block + sizeof(block) - 4, 0, 4);
    check_block("last-word-zero", block, sizeof(block) - 4, true);
    memset(block, 0x33, sizeof(block));
    check_block("unterminated", block, 0, false);
    puts("PSXtract auxiliary boundary regressions passed");
}
