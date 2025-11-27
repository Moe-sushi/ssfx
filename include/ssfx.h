// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ssfx, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2025 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 */
//
// !!! IMPORTANT NOTICE !!!
// THIS PROGRAM DOES NOT HAVE SUPER COW POWERS
// THIS PROGRAM WILL NOT WORK WHEN PLATFORM CPU ARCHITECTURE IS DIFFERENT
// PLEASE MAKE SURE THAT YOUR PROGRAM IS STATICALLY LINKED
// PLEASE MAKE SURE THAT TAR EXECUTABLE IS ALSO STATICALLY LINKED
// OTHERWISE, IT WILL EVEN NOT HAVE CROSS-LIBC COMPATIBILITY
//
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <linux/memfd.h>
#ifdef __ANDROID__
#include <sys/syscall.h>
#define memfd_create(...) syscall(SYS_memfd_create, __VA_ARGS__)
#endif
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
// SSFX definitions
#define SSFX_MAGIC_START 0x114514FA
#define SSFX_MAGIC_END 0x1919810A
#define SSFX_SPLITTER "\n==114514SSFXSPLITTER==\n"
#define SSFX_VERSION_MAJOR 0
#define SSFX_VERSION_MINOR 9
#define SSFX_VERSION_PATCH 9
#define SSFX_VERSION_STRING "0.9.9"
struct __attribute__((packed)) __attribute__((aligned(1))) ssfx_info {
	// SSFX information structure
	// For verfication
	uint32_t magic_start; // Magic number at the start
	uint64_t struct_size; // Size of this structure
	// File offsets and comments
	uint64_t self_end; // End of the main executable
	uint64_t file_0_start; // Start of file 0
	uint64_t file_0_end; // End of file 0
	uint64_t file_0_id; // ID of file 0
	char file_0_comment[512]; // Comment for file 0
	uint64_t file_1_start; // Start of file 1
	uint64_t file_1_end; // End of file 1
	uint64_t file_1_id; // ID of file 1
	char file_1_comment[512]; // Comment for file 1
	uint64_t file_2_start; // Start of file 2
	uint64_t file_2_end; // End of file 2
	uint64_t file_2_id; // ID of file 2
	char file_2_comment[512]; // Comment for file 2
	uint64_t file_3_start; // Start of file 3
	uint64_t file_3_end; // End of file 3
	uint64_t file_3_id; // ID of file 3
	char file_3_comment[512]; // Comment for file 3
	uint64_t file_4_start; // Start of file 4
	uint64_t file_4_end; // End of file 4
	uint64_t file_4_id; // ID of file 4
	char file_4_comment[512]; // Comment for file 4
	// Other information
	uint8_t ssfx_comment[512]; // Top-level comment
	uint8_t ssfx_id; // Just a code
	// For verfication
	uint8_t splitter[32]; // Splitter string
	uint32_t magic_end; // Magic number at the end
};
struct ssfx_pack {
	char *_Nullable self_path;
	char *_Nullable file_0_path;
	char *_Nullable file_0_comment;
	uint64_t file_0_id;
	char *_Nullable file_1_path;
	char *_Nullable file_1_comment;
	uint64_t file_1_id;
	char *_Nullable file_2_path;
	char *_Nullable file_2_comment;
	uint64_t file_2_id;
	char *_Nullable file_3_path;
	char *_Nullable file_3_comment;
	uint64_t file_3_id;
	char *_Nullable file_4_path;
	char *_Nullable file_4_comment;
	uint64_t file_4_id;
	char *_Nullable output_path;
	char *_Nullable ssfx_comment;
	uint8_t ssfx_id;
};
// Declarations
void ssfx_init_ssfx_pack(struct ssfx_pack *_Nonnull pack);
void ssfx_init_ssfx_info(struct ssfx_info *_Nonnull info);
int ssfx_load_a_elf_to_memory(const char *_Nullable path, uint64_t start, uint64_t end);
int ssfx_dump_a_file_to_disk(const char *_Nullable path, const char *_Nullable output_path, uint64_t start, uint64_t end);
int ssfx_proc_fs_works(void);
int ssfx_force_mount_procfs(void);
int ssfx_verify_ssfx_info(const char *_Nullable path);
struct ssfx_info ssfx_get_ssfx_info(const char *_Nullable path);
void ssfx_print_ssfx_info(const char *_Nonnull path);
int ssfx_append_file(FILE *_Nonnull in_fp, FILE *_Nonnull out_fp);
int ssfx_pack_ssfx(struct ssfx_pack *_Nonnull pack);
void ssfx_find_and_print_splitter_offsets(const char *_Nullable path);