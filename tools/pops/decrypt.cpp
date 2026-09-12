// Narrow adapter over John-K/pspdecrypt and PSXtract's libkirk PGD recipe.
// This translation unit includes the pinned decoder; it implements no cipher.
#include <climits>
#include <cstdint>
#include "PrxDecrypter.cpp"
extern "C" {
#include "libkirk/amctrl.h"
}
static uint32_t le32(const u8 *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
extern "C" int pops_decrypt(const u8 *psp, size_t n, const u8 *data, size_t dn, u8 *output) {
    if (n < 0x150 || n > INT_MAX || memcmp(psp, "~PSP", 4) || psp[0x7c] != 20 || le32(psp+0xd0) != 0x0daa06f0) return -10;
    const size_t declared = le32(psp+0x2c), compressed = le32(psp+0xb0), offset = le32(psp+0xb4);
    if (declared < 0x150 || declared > n || !compressed || compressed > INT_MAX || offset > declared-0xd0 ||
        ((compressed+15)&~size_t(15)) > declared-0xd0-offset) return -11;
    size_t pgd_offset;
    if (dn >= 12 && !memcmp(data,"PSISOIMG0000",12)) pgd_offset=0x400;
    else if (dn >= 13 && !memcmp(data,"PSTITLEIMG0000",13)) pgd_offset=0x200;
    else return -12;
    if (pgd_offset > dn || dn-pgd_offset < 0x90) return -13;
    u8 pgd[0x90]; memcpy(pgd,data+pgd_offset,sizeof pgd);
    if (memcmp(pgd,"\0PGD",4)) return -14;
    // Initial supported profile: no fuse-bound keys. Reject other profiles explicitly.
    if (le32(pgd+4)!=1 || le32(pgd+8)!=1) return -15;
    u8 dnas[16]={0xED,0xE2,0x5D,0x2D,0xBB,0xF8,0x12,0xE5,0x3C,0x5C,0x59,0x32,0xFA,0xE3,0xE2,0x43};
    u8 key[16]; MAC_KEY mac;
    kirk_init();
    if (sceDrmBBMacInit(&mac,1) || sceDrmBBMacUpdate(&mac,pgd,0x80) || sceDrmBBMacFinal2(&mac,pgd+0x80,dnas)) return -16;
    if (sceDrmBBMacInit(&mac,1) || sceDrmBBMacUpdate(&mac,pgd,0x70) || bbmac_getkey(&mac,pgd+0x70,key)) return -17;
    // pspdecrypt checks its header SHA1 and KIRK CMD1 authenticates the payload.
    return pspDecryptType5(psp,output,static_cast<u32>(declared),key);
}
