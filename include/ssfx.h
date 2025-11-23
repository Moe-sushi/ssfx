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
/*
 * - ssfx design:
 * stage 0: original ssfx executable
 * stage 1: ssfx master
 * stage 2: ssfx pack
 *
 * - original ssfx:
 * stage 0: self executable
 * stage 1: create ssfx master with self executable and tar executable
 * - ssfx master:
 * stage 0: self executable
 * stage 1: dump tar executable
 * stage 2: create ssfx pack with self executable, tar executable and tar file
 * - ssfx pack:
 * stage 0: self executable
 * stage 1: dump tar executable and tar file
 * stage 2: unpack tar file using tar executable
 * stage 3: run entrance point from unpacked files
 * - conclusion:
 * ssfx master can be created from original ssfx executable
 * ssfx pack can be created from ssfx master
 * ssfx pack can be unpacked and run to extract and execute the entrance point
 *
 * - detection:
 * self_is_valid_ssfx_master() to detect ssfx master
 * self_is_valid_ssfx_pack() to detect ssfx pack
 * self_is_valid_ssfx_other() to detect ssfx other
 * - conclusion:
 * a program with ssfx have 4 states:
 * normal executable - can only pack self to ssfx master or ssfx other
 * ssfx master - can dump original exe and tar exe, can create ssfx pack
 * ssfx pack - can unpack and run to extract and execute the entrance point
 * ssfx other - only for detection using self_is_valid_ssfx_other()
 * - in graphical way:
 * [normal executable] --pack with tar exe--> [ssfx master]
 * [ssfx master] --dump original exe || tar exe--> [original exe || tar exe]
 * [ssfx master] --pack with tar file & entrance point--> [ssfx pack]
 * [ssfx pack] --unpack & run--> [unpacked files & entrance point executed]
 * [normal executable] --pack as ssfx other--> [ssfx other]
 *
 * - creating ssfx master:
 * pack_ssfx_master(tar_exe, output_file)
 *
 * - creating ssfx pack:
 * pack_ssfx_file(tar_file, output_file, entrance_point)
 * - unpacking and running ssfx pack:
 * unpack_and_run_ssfx(path)
 *
 * - dumping original executable from ssfx master:
 * dump_origional_exe(output_file)
 * - dumping tar executable from ssfx master:
 * dump_tar_exe(output_file)
 *
 * - creating ssfx other:
 * pack_ssfx_other(output_file)
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/wait.h>
#define SSFX_MAGIC_START 0x114514FA
#define SSFX_MAGIC_END 0x1919810A
#define SSFX_SPLITTER "\n==114514SSFXSPLITTER==\n"
#define SSFX_VERSION_MAJOR 0
#define SSFX_VERSION_MINOR 9
#define SSFX_VERSION_PATCH 0
#define SSFX_VERSION_STRING "0.9.0"
struct __attribute__((packed)) __attribute__((aligned(1))) ssfx_info_pack {
	// SSFX information structure
	// magic_start and magic_end are used to verify the structure
	uint32_t magic_start; // Magic number at the start
	uint64_t tar_offset_start; // Tar file offset start
	uint64_t tar_offset_end; // Tar file offset end
	uint64_t file_offset_start; // File offset start
	uint64_t file_offset_end; // File offset end
	uint8_t splitter[32]; // Splitter string
	uint8_t entrance_point[256]; // Entrance point string
	uint32_t magic_end; // Magic number at the end
};
struct __attribute__((packed)) __attribute__((aligned(1))) ssfx_info_master {
	// SSFX information structure
	// magic_start and magic_end are used to verify the structure
	uint32_t magic_start; // Magic number at the start
	uint64_t tar_offset_start; // Tar file offset start
	uint64_t tar_offset_end; // Tar file offset end
	uint8_t splitter[32]; // Splitter string
	uint32_t magic_end; // Magic number at the end
};
struct __attribute__((packed)) __attribute__((aligned(1))) ssfx_info_other {
	// SSFX information structure
	// magic_start and magic_end are used to verify the structure
	uint32_t magic_start; // Magic number at the start
	uint8_t splitter[32]; // Splitter string
	uint32_t magic_end; // Magic number at the end
};
bool self_is_valid_ssfx_pack(void);
bool self_is_valid_ssfx_master(void);
bool self_is_valid_ssfx_other(void);
void pack_ssfx_master(const char *tar_exe, const char *output_file);
void pack_ssfx_file(const char *tar_file, const char *output_file, const char *entrance_point);
void unpack_and_run_ssfx(const char *path);
void dump_origional_exe(const char *output_file);
void dump_tar_exe(const char *output_file);
void pack_ssfx_other(const char *output_file);