// Linux platform operations for PSXtract-2 (GPL-3.0-or-later).
#include "native.h"
#include "utils.h"
#undef fopen

#include <array>
#include <cerrno>

extern "C" {
#include <libavutil/md5.h>
#include <libavutil/mem.h>
}

static char original_directory[PATH_MAX];

void save_original_working_directory() {
    if (!getcwd(original_directory, sizeof(original_directory))) {
        perror("ERROR: getcwd");
        exit(1);
    }
}

int get_exe_directory(char* buffer, int size) {
    if (size < 2) return -1;
    ssize_t length = readlink("/proc/self/exe", buffer, size - 1);
    if (length < 0 || length >= size - 1) return -1;
    buffer[length] = 0;
    char* slash = strrchr(buffer, '/');
    if (!slash) return -1;
    *slash = 0;
    return 0;
}

int build_output_path(const char* filename, char* output, int size) {
    // Disc names are filenames, never paths outside the extraction directory.
    if (!original_directory[0] || !filename[0] || strchr(filename, '/') || strchr(filename, '\\')) return -1;
    int length = snprintf(output, size, "%s/%s", original_directory, filename);
    return length >= 0 && length < size ? 0 : -1;
}

int utf8_file_exists(const char* filename) {
    return access(filename, F_OK);
}

FILE* utf8_fopen(const char* filename, const char* mode) {
    return fopen(filename, mode);
}

int select_cue_option(const char* title, const char* message, const char* options[], int count) {
    fprintf(stderr, "%s: %s\n", title, message);
    for (int i = 0; i < count; ++i) fprintf(stderr, "%d: %s\n", i + 1, options[i]);
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "ERROR: Ambiguous CUE requires interactive selection\n");
        return -1;
    }
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) return -1;
    char* end;
    errno = 0;
    long choice = strtol(line, &end, 10);
    return !errno && (*end == '\n' || *end == 0) && choice >= 1 && choice <= count ? choice - 1 : -1;
}

bool calculate_md5(const char* filename, char* output) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;
    AVMD5* md5 = av_md5_alloc();
    if (!md5) { fclose(file); return false; }
    av_md5_init(md5);
    std::array<unsigned char, 65536> buffer;
    size_t size;
    while ((size = fread(buffer.data(), 1, buffer.size(), file))) av_md5_update(md5, buffer.data(), size);
    bool okay = !ferror(file);
    if (fclose(file)) okay = false;
    unsigned char digest[16];
    av_md5_final(md5, digest);
    av_free(md5);
    if (okay) for (int i = 0; i < 16; ++i) snprintf(output + i * 2, 3, "%02x", digest[i]);
    return okay;
}
