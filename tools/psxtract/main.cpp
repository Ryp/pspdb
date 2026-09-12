// Thin DATA.BIN entry point to PSXtract; decoding remains in upstream code.
#define main psxtract_original_main
#include "psxtract.cpp"
#undef main
#include <climits>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: psxtract-data DATA.BIN NEW_OUTPUT_DIRECTORY\n");
        return 2;
    }
    FILE *input = fopen(argv[1], "rb");
    if (!input) { perror("input"); return 1; }
    fseek(input, 0, SEEK_END);
    long size = ftell(input);
    rewind(input);
    char magic[12];
    if (size < 0x100000 || size > INT_MAX ||
        fread(magic, 1, sizeof(magic), input) != sizeof(magic) ||
        memcmp(magic, iso_magic, sizeof(magic))) {
        fprintf(stderr, "Expected a single-disc PSISOIMG0000 payload (1 MiB–2 GiB).\n");
        fclose(input);
        return 1;
    }
    // Refuse existing directories: upstream uses fixed names and truncating writes.
    if (_mkdir(argv[2]) || _chdir(argv[2])) { perror("output"); fclose(input); return 1; }
    kirk_init();
    unsigned char key[16] = {};
    int start = extract_startdat(input, false);
    int result = decrypt_single_disc(input, (int)size, start, key, false);
    fclose(input);
    return result ? 1 : 0;
}
