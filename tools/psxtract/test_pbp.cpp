// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.cpp"
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

static void require(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "PBP regression: %s\n", message);
        exit(1);
    }
}

static void reject(const char* directory, const PBP_HEADER& header, size_t size) {
    require(mkdir(directory, 0700) == 0 && chdir(directory) == 0, "cannot isolate case");
    FILE* input = tmpfile();
    require(input != nullptr, "cannot create input");
    require(fwrite(&header, size, 1, input) == 1, "cannot write header");
    const unsigned char trailing[4] = {};
    if (size == sizeof(header))
        require(fwrite(trailing, sizeof(trailing), 1, input) == 1, "cannot write payload");
    require(fflush(input) == 0, "cannot flush input");
    require(unpack_pbp(input) != 0, "accepted invalid section table");
    for (const char* name : pbp_filenames)
        require(access(name, F_OK) != 0, "published bytes before complete validation");
    require(fclose(input) == 0 && chdir("..") == 0, "cannot close case");
}

int main() {
    PBP_HEADER header = {};
    memcpy(header.signature, pbp_sig, sizeof(pbp_sig));
    for (int& offset : header.offset) offset = sizeof(header);
    reject("short-header", header, 20);
    header.offset[7] += 5;
    reject("past-end", header, sizeof(header));
    header.offset[6] += 4;
    header.offset[7] = sizeof(header);
    reject("descending", header, sizeof(header));

    require(mkdir("bounded-copy", 0700) == 0 && chdir("bounded-copy") == 0, "cannot isolate copy");
    unsigned char payload[65539];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = i % 251;
    for (int i = 1; i < 8; ++i) header.offset[i] = sizeof(header) + sizeof(payload);
    FILE* input = tmpfile();
    require(input != nullptr, "cannot create valid input");
    const int descriptor = fileno(input);
    require(fwrite(&header, sizeof(header), 1, input) == 1 &&
            fwrite(payload, sizeof(payload), 1, input) == 1 && fflush(input) == 0, "cannot write valid input");
    require(unpack_pbp(input) == 0, "rejected valid sections");
    require(fcntl(descriptor, F_GETFD) != -1, "closed caller-owned input");
    require(fclose(input) == 0, "cannot close valid input");
    FILE* output = fopen("PARAM.SFO", "rb");
    require(output != nullptr, "missing copied section");
    unsigned char actual[sizeof(payload)];
    require(fread(actual, 1, sizeof(actual), output) == sizeof(actual) &&
            memcmp(actual, payload, sizeof(payload)) == 0 && fgetc(output) == EOF && !ferror(output),
            "section copy changed bytes or lost the partial final chunk");
    require(fclose(output) == 0, "cannot close copied section");
    for (int i = 1; i < 8; ++i)
        require(access(pbp_filenames[i], F_OK) != 0, "published an empty section");
    puts("PSXtract PBP boundary regressions passed");
}
