// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.cpp"

static void require(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "PGD regression: %s\n", message);
        exit(1);
    }
}

static void mac(unsigned char* output, unsigned char* input, int size, unsigned char* key) {
    MAC_KEY state;
    require(sceDrmBBMacInit(&state, 1) == 0 &&
            sceDrmBBMacUpdate(&state, input, size) == 0 &&
            sceDrmBBMacFinal(&state, output, key) == 0, "cannot authenticate fixture");
}

static void crypt(unsigned char* bytes, int size, unsigned char* seed, unsigned char* key) {
    CIPHER_KEY state;
    require(sceDrmBBCipherInit(&state, 1, 2, seed, key, 0) == 0 &&
            sceDrmBBCipherUpdate(&state, bytes, size) == 0 &&
            sceDrmBBCipherFinal(&state) == 0, "cannot encrypt fixture");
}

static void make_pgd(unsigned char* pgd, unsigned char* key, u32 block_size) {
    memset(pgd, 0, 0xb0);
    memcpy(pgd, "\0PGD", 4);
    const u32 one = 1, data_size = 16, data_offset = 0x90;
    memcpy(pgd + 4, &one, 4);
    memcpy(pgd + 8, &one, 4);
    memcpy(pgd + 0x44, &data_size, 4);
    memcpy(pgd + 0x48, &block_size, 4);
    memcpy(pgd + 0x4c, &data_offset, 4);
    for (int i = 0; i < 16; ++i) pgd[0x90 + i] = i;
    crypt(pgd + 0x90, 16, pgd + 0x30, key);
    mac(pgd + 0xa0, pgd + 0x90, 16, key);
    mac(pgd + 0x60, pgd + 0xa0, 16, key);
    crypt(pgd + 0x30, 0x30, pgd + 0x10, key);
    mac(pgd + 0x70, pgd, 0x70, key);
    mac(pgd + 0x80, pgd, 0x80, dnas_key1A90);
}

int main() {
    require(kirk_init() == 0, "cannot initialize KIRK");
    unsigned char key[16];
    memset(key, 0x31, sizeof(key)); // Public, generated fixture key; not a license.
    alignas(4) unsigned char pgd[0xb0];
    make_pgd(pgd, key, 16);
    require(decrypt_pgd(pgd, sizeof(pgd), 2, key) == 16, "rejected complete authenticated PGD");
    for (int i = 0; i < 16; ++i) require(pgd[0x90 + i] == i, "wrong plaintext");
    make_pgd(pgd, key, 16);
    require(decrypt_pgd(pgd, sizeof(pgd), 2, nullptr) == 16, "rejected auto-derived auxiliary key");
    for (int i = 0; i < 16; ++i) require(pgd[0x90 + i] == i, "wrong auto-derived plaintext");
    make_pgd(pgd, key, 16);
    // Header MACs remain valid; the final table byte is outside the input span.
    require(decrypt_pgd(pgd, sizeof(pgd) - 1, 2, key) == -1, "accepted a truncated authenticated MAC table");
    make_pgd(pgd, key, 0);
    require(decrypt_pgd(pgd, sizeof(pgd), 2, key) == -1, "accepted a zero block size");
    puts("PSXtract authenticated PGD boundary regressions passed");
}
