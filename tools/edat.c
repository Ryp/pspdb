/* Bounded EDAT format orchestration; cryptography is pinned make-npdata (GPL-3.0). */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Do not compile the upstream CLI, warning-only extraction, or key logging. */
#define PSPDB_EDAT_CRYPTO_ONLY
#include "make_npdata.c"

#define BLOCK_SIZE 16384U
#define MAX_PLAINTEXT (64U * 1024U * 1024U)
#define MAX_SOURCE (MAX_PLAINTEXT + (MAX_PLAINTEXT / BLOCK_SIZE) * 16U + 0x110U)

static uint32_t read_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t read_be64(const unsigned char *p)
{
    return ((uint64_t)read_be32(p) << 32) | read_be32(p + 4);
}

static int open_regular(const char *path, size_t minimum, size_t maximum, size_t *size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size < minimum || (uint64_t)st.st_size > maximum) {
        close(fd);
        return -1;
    }
    *size = (size_t)st.st_size;
    return fd;
}

/* Read a stable, bounded snapshot and reject both short reads and file growth. */
static int read_snapshot(int fd, unsigned char *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = read(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        offset += (size_t)count;
    }
    unsigned char extra;
    ssize_t count;
    do {
        count = read(fd, &extra, 1);
    } while (count < 0 && errno == EINTR);
    return count == 0 ? 0 : -1;
}

static int authenticate(unsigned char *data, size_t size, unsigned char *tag,
                        unsigned char *key, int hash_mode)
{
    unsigned char hash_key[16];
    generate_hash(hash_mode, 0, hash_key, key);
    return cmac_hash_compare(hash_key, 16, data, (int)size, tag);
}

static int decrypt_snapshot(unsigned char *source, size_t size,
                            unsigned char *rap, size_t *payload_offset, size_t *payload_size)
{
    if (memcmp(source, "NPD\0", 4) != 0)
        return -1;
    uint32_t version = read_be32(source + 4);
    uint32_t flags = read_be32(source + 0x80);
    uint64_t length = read_be64(source + 0x88);
    if ((version != 1 && version != 2) || read_be32(source + 8) != 2 ||
        (flags != 0 && flags != 0x0c) || (version == 1 && flags != 0) ||
        read_be32(source + 0x84) != BLOCK_SIZE || length > MAX_PLAINTEXT)
        return -1;

    size_t blocks = ((size_t)length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    size_t metadata_size = blocks * 16;
    size_t data_offset = 0x100 + metadata_size;
    size_t padded_size = ((size_t)length + 15) & ~(size_t)15;
    size_t data_end = data_offset + padded_size;
    /* The optional 16-byte footer is not plaintext or authenticated payload.
       The adapter retains the entire original wrapper, including this footer. */
    if (size != data_end && size != data_end + 16)
        return -1;

    unsigned char key[16];
    get_rif_key(rap, key);
    int hash_mode = (flags & EDAT_ENCRYPTED_KEY_FLAG) ? 0x10000002 : 0x02;
    int crypto_mode = hash_mode;
    /* This keyed header MAC covers all NPD bytes, including title_hash. The
       filename-dependent title-hash check cannot use a CAS object's filename. */
    if (!authenticate(source, 0xa0, source + 0xa0, key, hash_mode) ||
        !authenticate(source + 0x100, metadata_size, source + 0x90, key, hash_mode))
        return -1;

    unsigned char empty_iv[16] = {0};
    for (size_t block = 0; block < blocks; ++block) {
        unsigned char block_key[16] = {0};
        unsigned char derived_key[16];
        if (version == 2)
            memcpy(block_key, source + 0x60, 12);
        block_key[12] = (unsigned char)(block >> 24);
        block_key[13] = (unsigned char)(block >> 16);
        block_key[14] = (unsigned char)(block >> 8);
        block_key[15] = (unsigned char)block;
        aesecb128_encrypt(key, block_key, derived_key);
        size_t offset = block * BLOCK_SIZE;
        size_t block_size = padded_size - offset;
        if (block_size > BLOCK_SIZE)
            block_size = BLOCK_SIZE;
        unsigned char *ciphertext = source + data_offset + offset;
        unsigned char *iv = version == 1 ? empty_iv : source + 0x40;
        /* The patch makes upstream decrypt authenticate before in-place CBC.
           A failing block therefore cannot publish even partial plaintext. */
        if (!decrypt(hash_mode, crypto_mode, 0, ciphertext, ciphertext, (int)block_size,
                     derived_key, iv, derived_key, source + 0x100 + block * 16))
            return -1;
    }
    *payload_offset = data_offset;
    *payload_size = (size_t)length;
    return 0;
}

/* No output is opened until the complete source has authenticated. O_EXCL also
   rejects dangling symlinks and an output created since the initial check. */
static int write_plaintext(const char *path, const unsigned char *data, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = write(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        offset += (size_t)count;
    }
    if (close(fd) != 0) {
        unlink(path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--provenance") == 0) {
        puts("{\"name\":\"make-npdata\",\"options\":[\"upstream:"
             PSPDB_EDAT_UPSTREAM "\",\"authenticated-edat:1\"]}");
        return 0;
    }
    if (argc != 4) {
        fputs("usage: pspdb-edat SOURCE OUTPUT RAP\n", stderr);
        return 2;
    }
    struct stat st;
    if (lstat(argv[2], &st) == 0 || errno != ENOENT) {
        fputs("pspdb-edat: output already exists or cannot be inspected\n", stderr);
        return 1;
    }
    size_t size;
    int fd = open_regular(argv[1], 0x100, MAX_SOURCE, &size);
    if (fd < 0) {
        fputs("pspdb-edat: source must be a bounded regular EDAT file\n", stderr);
        return 1;
    }
    unsigned char *source = malloc(size);
    int failed = source == NULL || read_snapshot(fd, source, size) != 0;
    if (close(fd) != 0)
        failed = 1;
    if (failed) {
        free(source);
        fputs("pspdb-edat: cannot read complete source\n", stderr);
        return 1;
    }
    unsigned char rap[16];
    size_t rap_size;
    fd = open_regular(argv[3], sizeof(rap), sizeof(rap), &rap_size);
    failed = fd < 0;
    if (fd >= 0) {
        failed = read_snapshot(fd, rap, rap_size) != 0;
        if (close(fd) != 0)
            failed = 1;
    }
    if (failed) {
        free(source);
        fputs("pspdb-edat: RAP must be a readable 16-byte regular file\n", stderr);
        return 1;
    }
    size_t offset, length;
    if (decrypt_snapshot(source, size, rap, &offset, &length) != 0) {
        free(source);
        fputs("pspdb-edat: unsupported, malformed, or unauthenticated EDAT\n", stderr);
        return 1;
    }
    failed = write_plaintext(argv[2], source + offset, length) != 0;
    free(source);
    if (failed) {
        fputs("pspdb-edat: cannot create complete plaintext output\n", stderr);
        return 1;
    }
    return 0;
}
