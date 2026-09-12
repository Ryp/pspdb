// Regression: a back-reference fills the caller's output capacity.
#include "lz.h"
#include <cstdio>
#include <cstring>

int main() {
    unsigned char input[1024] = {
        0x06,0xff,0x84,0xcf,0x7b,0x15,0x89,0x09,
        0x0b,0x4e,0x91,0xcc,0x5c,0xb8,0x71,0x11,
        0x3a,0x87,0x74,0x51,0x31,0xda,0x52,0x6f
    };
    unsigned char output[19];
    memset(output, 0xa5, sizeof(output));
    int count = decompress(output + 1, input, 16);
    if (count != 16 || output[0] != 0xa5 || output[17] != 0xa5) return 1;
    for (int i = 1; i < 16; ++i) if (output[i] != 0) return 1;
    if (output[16] != 2) return 1;
    // A match that exceeds capacity must still fail, without touching guards.
    memset(output, 0xa5, sizeof(output));
    if (decompress(output + 1, input, 17) != -1 || output[0] != 0xa5 || output[18] != 0xa5) return 1;
    puts("PSXtract LZ boundary regression passed");
}
