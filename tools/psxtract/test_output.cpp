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
