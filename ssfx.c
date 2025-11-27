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
#include "include/ssfx.h"
void ssfx_init_ssfx_pack(struct ssfx_pack *_Nonnull pack)
{
	/*
	 * Initialize ssfx_pack structure
	 */
	memset(pack, 0, sizeof(struct ssfx_pack));
	pack->self_path = NULL;
	pack->self_comment = NULL;
	pack->self_id = 0;
	pack->file_0_path = NULL;
	pack->file_0_comment = NULL;
	pack->file_1_path = NULL;
	pack->file_1_comment = NULL;
	pack->file_2_path = NULL;
	pack->file_2_comment = NULL;
	pack->file_3_path = NULL;
	pack->file_3_comment = NULL;
	pack->file_4_path = NULL;
	pack->file_4_comment = NULL;
	pack->output_path = NULL;
	pack->ssfx_comment = NULL;
	pack->ssfx_id = 0;
	pack->file_0_id = 0;
	pack->file_1_id = 0;
	pack->file_2_id = 0;
	pack->file_3_id = 0;
	pack->file_4_id = 0;
}
void ssfx_init_ssfx_info(struct ssfx_info *_Nonnull info)
{
	/*
	 * Initialize ssfx_info structure
	 */
	memset(info, 0, sizeof(struct ssfx_info));
	info->magic_start = SSFX_MAGIC_START;
	info->struct_size = sizeof(struct ssfx_info);
	info->self_end = 0;
	info->self_id = 0;
	memset(info->self_comment, 0, sizeof(info->self_comment));
	info->file_0_start = 0;
	info->file_0_end = 0;
	memset(info->file_0_comment, 0, sizeof(info->file_0_comment));
	info->file_1_start = 0;
	info->file_1_end = 0;
	memset(info->file_1_comment, 0, sizeof(info->file_1_comment));
	info->file_2_start = 0;
	info->file_2_end = 0;
	memset(info->file_2_comment, 0, sizeof(info->file_2_comment));
	info->file_3_start = 0;
	info->file_3_end = 0;
	memset(info->file_3_comment, 0, sizeof(info->file_3_comment));
	info->file_4_start = 0;
	info->file_4_end = 0;
	memset(info->file_4_comment, 0, sizeof(info->file_4_comment));
	memset(info->ssfx_comment, 0, sizeof(info->ssfx_comment));
	info->ssfx_id = 0;
	memset(info->splitter, 0, sizeof(info->splitter));
	strcat((char *)info->splitter, SSFX_SPLITTER);
	info->magic_end = SSFX_MAGIC_END;
	info->file_0_id = 0;
	info->file_1_id = 0;
	info->file_2_id = 0;
	info->file_3_id = 0;
	info->file_4_id = 0;
}
int ssfx_load_a_elf_to_memory(const char *_Nullable path, uint64_t start, uint64_t end)
{
	/*
	 * Load a file segment to memory using memfd_create
	 * Return memfd file descriptor if successful
	 * Return -1 if failed
	 * If path is NULL, use /proc/self/exe
	 */
	if (path == NULL) {
		path = "/proc/self/exe";
	}
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		return -1;
	}
	// Get file size
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	// Validate offsets
	if (start > end || file_size < end) {
		fclose(fp);
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	char path_load[4096];
	sprintf(path_load, "%ld.%ld.ssfx.tmp", start, end);
	int ret = memfd_create(path_load, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (ret == -1) {
		fclose(fp);
		return -1;
	}
	fchmod(ret, S_IRUSR | S_IWUSR | S_IXUSR);
	char buffer[4096];
	fseek(fp, start, SEEK_SET);
	uint64_t to_read = end - start;
	uint64_t total_read = 0;
	// Read and write to memfd
	while (total_read < to_read) {
		size_t chunk_size = sizeof(buffer);
		if (to_read - total_read < chunk_size) {
			chunk_size = to_read - total_read;
		}
		size_t read_bytes = fread(buffer, 1, chunk_size, fp);
		if (read_bytes == 0) {
			break;
		}
		ssize_t written = write(ret, buffer, read_bytes);
		if (written == -1) {
			break;
		}
		total_read += written;
	}
	fclose(fp);
	fcntl(ret, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
	return ret;
}
int ssfx_dump_a_file_to_disk(const char *_Nullable path, const char *_Nullable output_path, uint64_t start, uint64_t end)
{
	/*
	 * Dump a file segment to disk
	 * Return 0 if successful
	 * Return -1 if failed
	 * If path is NULL, use /proc/self/exe
	 */
	if (path == NULL) {
		path = "/proc/self/exe";
	}
	if (output_path == NULL) {
		return -1;
	}
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		return -1;
	}
	// Get file size
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	// Validate offsets
	if (start > end || file_size < end) {
		fclose(fp);
		return -1;
	}
	fseek(fp, start, SEEK_SET);
	remove(output_path);
	rmdir(output_path);
	unlink(output_path);
	FILE *out_fp = fopen(output_path, "wb");
	if (out_fp == NULL) {
		fclose(fp);
		return -1;
	}
	char buffer[4096];
	uint64_t to_read = end - start;
	uint64_t total_read = 0;
	// Read and write to output file
	while (total_read < to_read) {
		size_t chunk_size = sizeof(buffer);
		if (to_read - total_read < chunk_size) {
			chunk_size = to_read - total_read;
		}
		size_t read_bytes = fread(buffer, 1, chunk_size, fp);
		if (read_bytes == 0) {
			break;
		}
		size_t written = fwrite(buffer, 1, read_bytes, out_fp);
		if (written == 0) {
			break;
		}
		total_read += written;
	}
	fclose(fp);
	fclose(out_fp);
	chmod(output_path, S_IRUSR | S_IWUSR | S_IXUSR);
	return 0;
}
int ssfx_proc_fs_works(void)
{
	/*
	 * Return 0 if /proc filesystem is not working
	 * otherwise return 1
	 */
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (fp == NULL) {
		return 0;
	}
	fclose(fp);
	return 1;
}
int ssfx_force_mount_procfs(void)
{
	/*
	 * Try to mount /proc filesystem
	 * Return -1 if failed
	 * Return 0 if successful
	 */
	if (geteuid() != 0) {
		return -1;
	}
	return mount("proc", "/proc", "proc", 0, NULL);
}
int ssfx_verify_ssfx_info(const char *_Nullable path)
{
	/*
	 * Verify SSFX information structure in the given file
	 * Return 0 if valid SSFX info found
	 * Return -1 if not found or invalid
	 * If path is NULL, use /proc/self/exe
	 */
	// Read ssfx_info structure from the end of the file
	if (path == NULL) {
		path = "/proc/self/exe";
	}
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		return -1;
	}
	fseek(fp, -((long)sizeof(struct ssfx_info)), SEEK_END);
	struct ssfx_info info;
	size_t read_bytes = fread(&info, 1, sizeof(struct ssfx_info), fp);
	if (read_bytes != sizeof(struct ssfx_info)) {
		fclose(fp);
		return -1;
	}
	// Verify magic numbers
	if (info.magic_start != SSFX_MAGIC_START || info.magic_end != SSFX_MAGIC_END) {
		fclose(fp);
		return -1;
	}
	// Verify struct size
	if (info.struct_size != sizeof(struct ssfx_info)) {
		fclose(fp);
		return -1;
	}
	// Verify splitter
	fseek(fp, -((long)sizeof(struct ssfx_info)) - sizeof(info.splitter), SEEK_END);
	char splitter_check[sizeof(info.splitter)];
	read_bytes = fread(splitter_check, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	// Verify splitter after self_end
	fseek(fp, info.self_end, SEEK_SET);
	char splitter_check_2[sizeof(info.splitter)];
	read_bytes = fread(splitter_check_2, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check_2, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	if (info.file_0_start == 0) {
		fclose(fp);
		return 0;
	}
	// Verify splitter before file_0_start
	fseek(fp, info.file_0_start - sizeof(info.splitter), SEEK_SET);
	char splitter_check_3[sizeof(info.splitter)];
	read_bytes = fread(splitter_check_3, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check_3, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	if (info.file_1_start == 0) {
		fclose(fp);
		return 0;
	}
	// Verify splitter before file_1_start
	fseek(fp, info.file_1_start - sizeof(info.splitter), SEEK_SET);
	char splitter_check_4[sizeof(info.splitter)];
	read_bytes = fread(splitter_check_4, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check_4, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	if (info.file_2_start == 0) {
		fclose(fp);
		return 0;
	}
	// Verify splitter before file_2_start
	fseek(fp, info.file_2_start - sizeof(info.splitter), SEEK_SET);
	char splitter_check_5[sizeof(info.splitter)];
	read_bytes = fread(splitter_check_5, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check_5, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	if (info.file_3_start == 0) {
		fclose(fp);
		return 0;
	}
	// Verify splitter before file_3_start
	fseek(fp, info.file_3_start - sizeof(info.splitter), SEEK_SET);
	char splitter_check_6[sizeof(info.splitter)];
	read_bytes = fread(splitter_check_6, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check_6, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	if (info.file_4_start == 0) {
		fclose(fp);
		return 0;
	}
	// Verify splitter before file_4_start
	fseek(fp, info.file_4_start - sizeof(info.splitter), SEEK_SET);
	char splitter_check_7[sizeof(info.splitter)];
	read_bytes = fread(splitter_check_7, 1, sizeof(info.splitter), fp);
	if (read_bytes != sizeof(info.splitter)) {
		fclose(fp);
		return -1;
	}
	if (memcmp(splitter_check_7, info.splitter, sizeof(info.splitter)) != 0) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}
struct ssfx_info ssfx_get_ssfx_info(const char *_Nullable path)
{
	/*
	 * Get SSFX information structure from the given file
	 * If not found or invalid, return zeroed structure
	 * If path is NULL, use /proc/self/exe
	 */
	// Read ssfx_info structure from the end of the file
	struct ssfx_info info;
	memset(&info, 0, sizeof(struct ssfx_info));
	if (ssfx_verify_ssfx_info(path) != 0) {
		return info;
	}
	if (path == NULL) {
		path = "/proc/self/exe";
	}
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		return info;
	}
	fseek(fp, -((long)sizeof(struct ssfx_info)), SEEK_END);
	size_t read_bytes = fread(&info, 1, sizeof(struct ssfx_info), fp);
	if (read_bytes != sizeof(struct ssfx_info)) {
		fclose(fp);
		memset(&info, 0, sizeof(struct ssfx_info));
		return info;
	}
	fclose(fp);
	return info;
}
void ssfx_print_ssfx_info(const char *_Nonnull path)
{
	/*
	 * Print SSFX information structure from the given file
	 * If path is NULL, use /proc/self/exe
	 */
	if (path == NULL) {
		path = "/proc/self/exe";
	}
	if (ssfx_verify_ssfx_info(path) != 0) {
		printf("No SSFX info or invalid SSFX info in %s\n", path);
		return;
	}
	struct ssfx_info info = ssfx_get_ssfx_info(path);
	printf("SSFX Information:\n");
	printf("  SSFX ID: %lu\n", info.ssfx_id);
	printf("  SSFX Comment: %s\n", info.ssfx_comment);
	printf("  Self End Offset: %lu\n", info.self_end);
	printf("  Self ID: %lu\n", info.self_id);
	printf("  Self Comment: %s\n", info.self_comment);
	printf("  File 0: ID=%lu, Start=%lu, End=%lu, Comment=%s\n", info.file_0_id, info.file_0_start, info.file_0_end, info.file_0_comment);
	printf("  File 1: ID=%lu, Start=%lu, End=%lu, Comment=%s\n", info.file_1_id, info.file_1_start, info.file_1_end, info.file_1_comment);
	printf("  File 2: ID=%lu, Start=%lu, End=%lu, Comment=%s\n", info.file_2_id, info.file_2_start, info.file_2_end, info.file_2_comment);
	printf("  File 3: ID=%lu, Start=%lu, End=%lu, Comment=%s\n", info.file_3_id, info.file_3_start, info.file_3_end, info.file_3_comment);
	printf("  File 4: ID=%lu, Start=%lu, End=%lu, Comment=%s\n", info.file_4_id, info.file_4_start, info.file_4_end, info.file_4_comment);
}
int ssfx_append_file(FILE *_Nonnull in_fp, FILE *_Nonnull out_fp)
{
	/*
	 * Append the content of in_fp to out_fp
	 * Return 0 if successful
	 * Return -1 if failed
	 */
	fseek(in_fp, 0, SEEK_SET);
	fseek(out_fp, 0, SEEK_END);
	char buffer[4096];
	size_t read_bytes;
	while ((read_bytes = fread(buffer, 1, sizeof(buffer), in_fp)) > 0) {
		size_t written = fwrite(buffer, 1, read_bytes, out_fp);
		if (written != read_bytes) {
			return -1;
		}
	}
	return 0;
}
int ssfx_pack_ssfx(struct ssfx_pack *_Nonnull pack)
{
	/*
	 * Pack files into an SSFX executable
	 * Return 0 if successful
	 * Return -1 if failed
	 * If pack->self_path is NULL, use /proc/self/exe
	 */
	struct ssfx_info info;
	ssfx_init_ssfx_info(&info);
	// Open self executable
	const char *self_path = pack->self_path;
	if (self_path == NULL) {
		self_path = "/proc/self/exe";
	}
	FILE *self_fp = fopen(self_path, "rb");
	if (self_fp == NULL) {
		return -1;
	}
	// Open output file
	const char *output_path = pack->output_path;
	if (output_path == NULL) {
		return -1;
	}
	remove(output_path);
	rmdir(output_path);
	unlink(output_path);
	FILE *out_fp = fopen(output_path, "wb");
	if (out_fp == NULL) {
		fclose(self_fp);
		return -1;
	}
	info.ssfx_id = pack->ssfx_id;
	info.self_id = pack->self_id;
	if (pack->ssfx_comment != NULL) {
		strncpy((char *)info.ssfx_comment, pack->ssfx_comment, sizeof(info.ssfx_comment) - 1);
	}
	if (pack->self_comment != NULL) {
		strncpy((char *)info.self_comment, pack->self_comment, sizeof(info.self_comment) - 1);
	}
	// Get self file size
	fseek(self_fp, 0, SEEK_END);
	uint64_t self_size = ftell(self_fp);
	fseek(self_fp, 0, SEEK_SET);
	// Copy self executable to output
	ssfx_append_file(self_fp, out_fp);
	fclose(self_fp);
	info.self_end = self_size;
	// Append splitter
	FILE *splitter_fp = fmemopen(info.splitter, sizeof(info.splitter), "r");
	ssfx_append_file(splitter_fp, out_fp);
	// Append file 0
	if (pack->file_0_path == NULL) {
		goto end;
	} else {
		info.file_0_start = ftell(out_fp);
		info.file_0_id = pack->file_0_id;
		if (pack->file_0_comment != NULL) {
			strncpy((char *)info.file_0_comment, pack->file_0_comment, sizeof(info.file_0_comment) - 1);
		}
		FILE *file_0_fp = fopen(pack->file_0_path, "rb");
		if (file_0_fp == NULL) {
			fclose(splitter_fp);
			fclose(out_fp);
			return -1;
		}
		ssfx_append_file(file_0_fp, out_fp);
		fclose(file_0_fp);
		info.file_0_end = ftell(out_fp);
		// Append splitter
		ssfx_append_file(splitter_fp, out_fp);
	}
	// Append file 1
	if (pack->file_1_path == NULL) {
		goto end;
	} else {
		info.file_1_start = ftell(out_fp);
		info.file_1_id = pack->file_1_id;
		if (pack->file_1_comment != NULL) {
			strncpy((char *)info.file_1_comment, pack->file_1_comment, sizeof(info.file_1_comment) - 1);
		}
		FILE *file_1_fp = fopen(pack->file_1_path, "rb");
		if (file_1_fp == NULL) {
			fclose(splitter_fp);
			fclose(out_fp);
			return -1;
		}
		ssfx_append_file(file_1_fp, out_fp);
		fclose(file_1_fp);
		info.file_1_end = ftell(out_fp);
		// Append splitter
		ssfx_append_file(splitter_fp, out_fp);
	}
	// Append file 2
	if (pack->file_2_path == NULL) {
		goto end;
	} else {
		info.file_2_start = ftell(out_fp);
		info.file_2_id = pack->file_2_id;
		if (pack->file_2_comment != NULL) {
			strncpy((char *)info.file_2_comment, pack->file_2_comment, sizeof(info.file_2_comment) - 1);
		}
		FILE *file_2_fp = fopen(pack->file_2_path, "rb");
		if (file_2_fp == NULL) {
			fclose(splitter_fp);
			fclose(out_fp);
			return -1;
		}
		ssfx_append_file(file_2_fp, out_fp);
		fclose(file_2_fp);
		info.file_2_end = ftell(out_fp);
		// Append splitter
		ssfx_append_file(splitter_fp, out_fp);
	}
	// Append file 3
	if (pack->file_3_path == NULL) {
		goto end;
	} else {
		info.file_3_start = ftell(out_fp);
		info.file_3_id = pack->file_3_id;
		if (pack->file_3_comment != NULL) {
			strncpy((char *)info.file_3_comment, pack->file_3_comment, sizeof(info.file_3_comment) - 1);
		}
		FILE *file_3_fp = fopen(pack->file_3_path, "rb");
		if (file_3_fp == NULL) {
			fclose(splitter_fp);
			fclose(out_fp);
			return -1;
		}
		ssfx_append_file(file_3_fp, out_fp);
		fclose(file_3_fp);
		info.file_3_end = ftell(out_fp);
		// Append splitter
		ssfx_append_file(splitter_fp, out_fp);
	}
	// Append file 4
	if (pack->file_4_path == NULL) {
		goto end;
	} else {
		info.file_4_start = ftell(out_fp);
		info.file_4_id = pack->file_4_id;
		if (pack->file_4_comment != NULL) {
			strncpy((char *)info.file_4_comment, pack->file_4_comment, sizeof(info.file_4_comment) - 1);
		}
		FILE *file_4_fp = fopen(pack->file_4_path, "rb");
		if (file_4_fp == NULL) {
			fclose(splitter_fp);
			fclose(out_fp);
			return -1;
		}
		ssfx_append_file(file_4_fp, out_fp);
		fclose(file_4_fp);
		info.file_4_end = ftell(out_fp);
		// Append splitter
		ssfx_append_file(splitter_fp, out_fp);
	}
end:
	// Append info structure
	fseek(out_fp, 0, SEEK_END);
	fwrite(&info, 1, sizeof(info), out_fp);
	// Clean up
	fclose(splitter_fp);
	fclose(out_fp);
	chmod(output_path, S_IRUSR | S_IWUSR | S_IXUSR);
	return 0;
}
void ssfx_find_and_print_splitter_offsets(const char *_Nullable path)
{
	/*
	 * Find and print all splitter offsets in the given file
	 * Only for debugging.
	 * If path is NULL, use /proc/self/exe
	 */
	// Read the entire file and search for splitter occurrences
	if (path == NULL) {
		path = "/proc/self/exe";
	}
	struct ssfx_info info;
	// Open file
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
	// Read ssfx_info structure from the end of the file
	fseek(fp, -((long)sizeof(struct ssfx_info)), SEEK_END);
	size_t read_bytes = fread(&info, 1, sizeof(struct ssfx_info), fp);
	if (read_bytes != sizeof(struct ssfx_info)) {
		perror("Failed to read ssfx_info");
		fclose(fp);
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	// Read self to memory.
	char *file_buffer = (char *)malloc(file_size);
	if (!file_buffer) {
		perror("Failed to allocate memory");
		fclose(fp);
		exit(EXIT_FAILURE);
	}
	fread(file_buffer, 1, file_size, fp);
	fclose(fp);
	// Search for splitter occurrences.
	uint64_t offset = 0;
	int found_count = 0;
	while (offset < file_size - sizeof(info.splitter)) {
		if (memcmp(file_buffer + offset, info.splitter, sizeof(info.splitter)) == 0) {
			printf("Found splitter %d at offset: %lu, after splitter is %lu\n", found_count, offset, offset + sizeof(info.splitter));
			found_count++;
		}
		offset++;
	}
	free(file_buffer);
}