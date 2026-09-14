// Linux platform boundary for PSXtract-2 (GPL-3.0-or-later).
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#define _fseeki64 fseeko
#define _ftelli64 ftello
#define _chdir chdir
#define _rmdir rmdir
#define _getcwd getcwd
#define _strdup strdup
#define _mkdir(path) mkdir(path, 0700)
#define _MAX_PATH PATH_MAX
#define MAX_PATH PATH_MAX

int decode_atrac3(const char* input, const char* output);
int select_cue_option(const char* title, const char* message, const char* options[], int count);
