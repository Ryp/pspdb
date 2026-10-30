// SPDX-License-Identifier: GPL-3.0-or-later
#define main psxtract_cli_main
#include "psxtract.cpp"
#undef main

static void require(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "Output regression: %s\n", message);
        exit(1);
    }
}

int main() {
    save_original_working_directory();
    char generated[256];
    generated_output_title(generated, sizeof(generated), 0);
    require(check_output_files_overwrite(generated, false), "rejected absent generated outputs");
    FILE* stream = fopen("cdrom.cue", "w");
    require(stream && fclose(stream) == 0, "cannot create generated CUE fixture");
    require(!check_output_files_overwrite(generated, false), "missed lowercase generated CUE");
    require(unlink("cdrom.cue") == 0, "cannot remove generated CUE fixture");
    stream = fopen("cdrom_2.bin", "w");
    require(stream && fclose(stream) == 0, "cannot create generated disc BIN fixture");
    generated_output_title(generated, sizeof(generated), 2);
    require(strcmp(generated, "cdrom_2") == 0, "wrong generated disc title");
    require(!check_output_files_overwrite(generated, false), "missed lowercase generated disc BIN");
    require(unlink("cdrom_2.bin") == 0, "cannot remove generated disc BIN fixture");
    require(check_output_files_overwrite("disc", false), "rejected absent outputs");
    require(symlink("missing-target", "disc.cue") == 0, "cannot create dangling link");
    require(!check_output_files_overwrite("disc", false), "accepted dangling CUE link");
    struct stat entry;
    require(lstat("disc.cue", &entry) == 0 && S_ISLNK(entry.st_mode), "changed output link");
    require(lstat("missing-target", &entry) != 0 && errno == ENOENT, "created link target");
    require(unlink("disc.cue") == 0, "cannot remove fixture link");
    require(mkfifo("disc.bin", 0600) == 0, "cannot create FIFO");
    require(!check_output_files_overwrite("disc", false), "accepted FIFO output");
    require(unlink("disc.bin") == 0, "cannot remove FIFO");
    require(mkdir("disc.cue", 0700) == 0, "cannot create output directory");
    require(!check_output_files_overwrite("disc", true), "accepted directory output");
    puts("PSXtract output-entry regression passed");
}
