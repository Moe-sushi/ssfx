#include "include/ssfx.h"
bool self_is_valid_ssfx_pack(void)
{
	/*
	 * Verify the SSFX info structure by checking magic numbers and splitters.
	 * Also checks that offsets are within file size.
	 */
	struct ssfx_info_pack *info = malloc(sizeof(struct ssfx_info_pack));
	if (!info) {
		return false;
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		free(info);
		return false;
	}
	fseek(fp, -sizeof(struct ssfx_info_pack), SEEK_END);
	fread(info, sizeof(struct ssfx_info_pack), 1, fp);
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		free(info);
		return false;
	}
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (info->tar_offset_end > file_size || info->file_offset_end > file_size) {
		free(info);
		return false;
	}
	// goto tar offset start and verify splitter
	fseek(fp, info->tar_offset_start - sizeof(info->splitter), SEEK_SET);
	uint8_t splitter_check[sizeof(info->splitter)];
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		free(info);
		return false;
	}
	// goto file offset start and verify splitter
	fseek(fp, 0, SEEK_SET);
	fseek(fp, info->file_offset_start - sizeof(info->splitter), SEEK_SET);
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		free(info);
		return false;
	}
	// goto file end and verify splitter
	fseek(fp, 0, SEEK_SET);
	fseek(fp, info->file_offset_end, SEEK_SET);
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		free(info);
		return false;
	}
	fclose(fp);
	free(info);
	return true;
}
bool self_is_valid_ssfx_master(void)
{
	/*
	 * Verify the SSFX info structure by checking magic numbers and splitters.
	 * Also checks that offsets are within file size.
	 */
	struct ssfx_info_master *info = malloc(sizeof(struct ssfx_info_master));
	if (!info) {
		return false;
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		free(info);
		return false;
	}
	fseek(fp, -sizeof(struct ssfx_info_master), SEEK_END);
	fread(info, sizeof(struct ssfx_info_master), 1, fp);
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		free(info);
		return false;
	}
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (info->tar_offset_end > file_size) {
		free(info);
		return false;
	}
	// goto tar offset start and verify splitter
	fseek(fp, info->tar_offset_start - sizeof(info->splitter), SEEK_SET);
	uint8_t splitter_check[sizeof(info->splitter)];
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		free(info);
		return false;
	}
	// goto tar end and verify splitter
	fseek(fp, 0, SEEK_SET);
	fseek(fp, info->tar_offset_end, SEEK_SET);
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		free(info);
		return false;
	}
	fclose(fp);
	free(info);
	return true;
}
bool self_is_valid_ssfx_other(void)
{
	/*
	 * Verify the SSFX other info structure by checking magic numbers and splitters.
	 */
	struct ssfx_info_other *info = malloc(sizeof(struct ssfx_info_other));
	if (!info) {
		return false;
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		free(info);
		return false;
	}
	fseek(fp, -sizeof(struct ssfx_info_other), SEEK_END);
	fread(info, sizeof(struct ssfx_info_other), 1, fp);
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		free(info);
		return false;
	}
	// goto end and verify splitter
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fseek(fp, file_size - sizeof(struct ssfx_info_other) - sizeof(info->splitter), SEEK_SET);
	uint8_t splitter_check[sizeof(info->splitter)];
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		free(info);
		return false;
	}
	fclose(fp);
	free(info);
	return true;
}
static void append_file(FILE *src, FILE *dest)
{
	/*
	 * Append contents of src file to dest file.
	 */
	uint8_t buffer[4096];
	size_t bytes_read;
	while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
		if (fwrite(buffer, 1, bytes_read, dest) != bytes_read) {
			perror("Failed to write to destination file");
			exit(EXIT_FAILURE);
		}
	}
}
void pack_ssfx_master(const char *tar_exe, const char *output_file)
{
	/*
	 * Pack the SSFX file by appending tar_exe and tar_file to self executable.
	 */
	FILE *fp_tar_exe = fopen(tar_exe, "rb");
	if (!fp_tar_exe) {
		perror("Failed to open tar_exe file");
		exit(EXIT_FAILURE);
	}
	remove(output_file);
	unlink(output_file);
	rmdir(output_file);
	FILE *fp_output = fopen(output_file, "wb");
	if (!fp_output) {
		perror("Failed to open output_file file");
		exit(EXIT_FAILURE);
	}
	FILE *self = fopen("/proc/self/exe", "rb");
	if (!self) {
		perror("Failed to open self executable");
		exit(EXIT_FAILURE);
	}
	uint8_t splitter[32];
	memset(splitter, 0, sizeof(splitter));
	strcpy((char *)splitter, SSFX_SPLITTER);
	uint64_t splitter_size = sizeof(splitter);
	FILE *splitter_fp = fmemopen(splitter, splitter_size, "rb");
	fseek(self, 0, SEEK_END);
	uint64_t self_size = ftell(self);
	fseek(self, 0, SEEK_SET);
	fseek(fp_tar_exe, 0, SEEK_END);
	uint64_t tar_exe_size = ftell(fp_tar_exe);
	fseek(fp_tar_exe, 0, SEEK_SET);
	// Copy self executable to output
	fseek(self, 0, SEEK_SET);
	append_file(self, fp_output);
	fclose(self);
	fseek(splitter_fp, 0, SEEK_SET);
	append_file(splitter_fp, fp_output);
	// Copy tar_exe to output
	fseek(fp_tar_exe, 0, SEEK_SET);
	append_file(fp_tar_exe, fp_output);
	fclose(fp_tar_exe);
	fseek(splitter_fp, 0, SEEK_SET);
	append_file(splitter_fp, fp_output);
	struct ssfx_info_master info;
	info.magic_start = SSFX_MAGIC_START;
	info.tar_offset_start = self_size + splitter_size;
	info.tar_offset_end = info.tar_offset_start + tar_exe_size;
	memset(info.splitter, 0, sizeof(info.splitter));
	memccpy((char *)info.splitter, SSFX_SPLITTER, 0, sizeof(info.splitter));
	info.magic_end = SSFX_MAGIC_END;
	FILE *info_fp = fmemopen(&info, sizeof(info), "rb");
	append_file(info_fp, fp_output);
	fclose(info_fp);
	fclose(fp_output);
	fclose(splitter_fp);
	chmod(output_file, 0755);
}

void pack_ssfx_file(const char *tar_file, const char *output_file, const char *entrance_point)
{
	/*
	 * Pack the SSFX file by appending tar_exe and tar_file to self executable.
	 */
	if (!self_is_valid_ssfx_master()) {
		printf("Current executable is not a valid SSFX master file.\n");
		exit(EXIT_FAILURE);
	}
	dump_tar_exe("./ssfx_tmp_tar_exe");
	FILE *fp_tar_exe = fopen("./ssfx_tmp_tar_exe", "rb");
	if (!fp_tar_exe) {
		perror("Failed to open tar_exe file");
		exit(EXIT_FAILURE);
	}
	FILE *fp_tar_file = fopen(tar_file, "rb");
	if (!fp_tar_file) {
		perror("Failed to open tar_file file");
		exit(EXIT_FAILURE);
	}
	remove(output_file);
	unlink(output_file);
	rmdir(output_file);
	FILE *fp_output = fopen(output_file, "wb");
	if (!fp_output) {
		perror("Failed to open output_file file");
		exit(EXIT_FAILURE);
	}
	FILE *self = fopen("/proc/self/exe", "rb");
	if (!self) {
		perror("Failed to open self executable");
		exit(EXIT_FAILURE);
	}
	uint8_t splitter[32];
	memset(splitter, 0, sizeof(splitter));
	strcpy((char *)splitter, SSFX_SPLITTER);
	uint64_t splitter_size = sizeof(splitter);
	FILE *splitter_fp = fmemopen(splitter, splitter_size, "rb");
	fseek(self, 0, SEEK_END);
	uint64_t self_size = ftell(self);
	fseek(self, 0, SEEK_SET);
	fseek(fp_tar_exe, 0, SEEK_END);
	uint64_t tar_exe_size = ftell(fp_tar_exe);
	fseek(fp_tar_exe, 0, SEEK_SET);
	fseek(fp_tar_file, 0, SEEK_END);
	uint64_t tar_file_size = ftell(fp_tar_file);
	fseek(fp_tar_file, 0, SEEK_SET);
	// Copy self executable to output
	fseek(self, 0, SEEK_SET);
	append_file(self, fp_output);
	fclose(self);
	fseek(splitter_fp, 0, SEEK_SET);
	append_file(splitter_fp, fp_output);
	// Copy tar_exe to output
	fseek(fp_tar_exe, 0, SEEK_SET);
	append_file(fp_tar_exe, fp_output);
	fclose(fp_tar_exe);
	fseek(splitter_fp, 0, SEEK_SET);
	append_file(splitter_fp, fp_output);
	// Copy tar_file to output
	fseek(fp_tar_file, 0, SEEK_SET);
	append_file(fp_tar_file, fp_output);
	fclose(fp_tar_file);
	fseek(splitter_fp, 0, SEEK_SET);
	append_file(splitter_fp, fp_output);
	struct ssfx_info_pack info;
	info.magic_start = SSFX_MAGIC_START;
	info.tar_offset_start = self_size + splitter_size;
	info.tar_offset_end = info.tar_offset_start + tar_exe_size;
	info.file_offset_start = info.tar_offset_end + splitter_size;
	info.file_offset_end = info.file_offset_start + tar_file_size;
	memset(info.splitter, 0, sizeof(info.splitter));
	memccpy((char *)info.splitter, SSFX_SPLITTER, 0, sizeof(info.splitter));
	memset(info.entrance_point, 0, sizeof(info.entrance_point));
	memccpy((char *)info.entrance_point, entrance_point, 0, sizeof(info.entrance_point));
	info.magic_end = SSFX_MAGIC_END;
	FILE *info_fp = fmemopen(&info, sizeof(info), "rb");
	append_file(info_fp, fp_output);
	fclose(info_fp);
	fclose(fp_output);
	fclose(splitter_fp);
	chmod(output_file, 0755);
	remove("./ssfx_tmp_tar_exe");
}
static int fork_and_exec(const char *path, char *const argv[])
{
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	} else if (pid == 0) {
		execv(path, argv);
		exit(EXIT_FAILURE);
	} else {
		int status;
		waitpid(pid, &status, 0);
		return status;
	}
}
void unpack_and_run_ssfx(const char *path)
{
	/*
	 * Unpack the SSFX contents to the specified path.
	 * Then run the entrance point from the unpacked files.
	 */
	if (path == NULL) {
		path = "./ssfx_unpack";
	}
	if (!self_is_valid_ssfx_pack()) {
		printf("This executable is not a valid SSFX file.\n");
		exit(EXIT_FAILURE);
	}
	rmdir(path);
	unlink(path);
	remove(path);
	if (mkdir(path, 0755) != 0) {
		perror("Failed to create directory for unpacking self");
		exit(EXIT_FAILURE);
	}
	chdir(path);
	FILE *self = fopen("/proc/self/exe", "rb");
	if (!self) {
		perror("Failed to open self executable for unpacking");
		exit(EXIT_FAILURE);
	}
	FILE *tar_exe_fp = fopen("ssfx_tmp_tar_exe", "wb");
	if (!tar_exe_fp) {
		perror("Failed to create temporary tar executable file");
		exit(EXIT_FAILURE);
	}
	FILE *tar_file_fp = fopen("ssfx_tmp_file.tar", "wb");
	if (!tar_file_fp) {
		perror("Failed to create temporary tar file");
		exit(EXIT_FAILURE);
	}
	struct ssfx_info_pack info;
	fseek(self, -sizeof(struct ssfx_info_pack), SEEK_END);
	fread(&info, sizeof(struct ssfx_info_pack), 1, self);
	if (info.magic_start != SSFX_MAGIC_START || info.magic_end != SSFX_MAGIC_END) {
		printf("Invalid SSFX info structure during unpacking.\n");
		exit(EXIT_FAILURE);
	}
	// Extract tar executable
	fseek(self, info.tar_offset_start, SEEK_SET);
	uint64_t tar_exe_size = info.tar_offset_end - info.tar_offset_start;
	char buffer[4096];
	uint64_t bytes_remaining = tar_exe_size;
	while (bytes_remaining > 0) {
		size_t bytes_to_read = (bytes_remaining < sizeof(buffer)) ? bytes_remaining : sizeof(buffer);
		size_t bytes_read = fread(buffer, 1, bytes_to_read, self);
		if (bytes_read == 0) {
			exit(EXIT_FAILURE);
		}
		fwrite(buffer, 1, bytes_read, tar_exe_fp);
		bytes_remaining -= bytes_read;
	}
	fclose(tar_exe_fp);
	chmod("ssfx_tmp_tar_exe", 0755);
	// Extract tar file
	fseek(self, info.file_offset_start, SEEK_SET);
	uint64_t tar_file_size = info.file_offset_end - info.file_offset_start;
	bytes_remaining = tar_file_size;
	while (bytes_remaining > 0) {
		size_t bytes_to_read = (bytes_remaining < sizeof(buffer)) ? bytes_remaining : sizeof(buffer);
		size_t bytes_read = fread(buffer, 1, bytes_to_read, self);
		if (bytes_read == 0) {
			perror("Failed to read tar file data");
			exit(EXIT_FAILURE);
		}
		fwrite(buffer, 1, bytes_read, tar_file_fp);
		bytes_remaining -= bytes_read;
	}
	fclose(tar_file_fp);
	fclose(self);
	chmod("ssfx_tmp_file.tar", 0644);
	// Use the extracted tar executable to unpack the tar file
	char *tar_argv[] = { "./ssfx_tmp_tar_exe", "-xpf", "ssfx_tmp_file.tar", NULL };
	if (fork_and_exec("./ssfx_tmp_tar_exe", tar_argv) != 0) {
		perror("Failed to unpack tar file");
		exit(EXIT_FAILURE);
	}
	remove("ssfx_tmp_tar_exe");
	remove("ssfx_tmp_file.tar");
	// Run the entrance point from the unpacked files
	chmod((char *)info.entrance_point, 0755);
	char *entrance_argv[] = { (char *)info.entrance_point, NULL };
	int status = fork_and_exec((char *)info.entrance_point, entrance_argv);
	exit(WEXITSTATUS(status));
}
void dump_tar_exe(const char *output_file)
{
	/*
	 * Dump the embedded tar executable to the specified output file.
	 */
	if (!self_is_valid_ssfx_master()) {
		printf("This executable is not a valid SSFX master file.\n");
		exit(EXIT_FAILURE);
	}
	struct ssfx_info_master *info = malloc(sizeof(struct ssfx_info_master));
	if (!info) {
		perror("Failed to allocate memory for ssfx_info_master");
		exit(EXIT_FAILURE);
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
	fseek(fp, -sizeof(struct ssfx_info_master), SEEK_END);
	fread(info, sizeof(struct ssfx_info_master), 1, fp);
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		printf("Invalid SSFX master info structure.\n");
		exit(EXIT_FAILURE);
	}
	fseek(fp, info->tar_offset_start, SEEK_SET);
	FILE *out_fp = fopen(output_file, "wb");
	if (!out_fp) {
		perror("Failed to open output file for tar executable");
		exit(EXIT_FAILURE);
	}
	uint64_t tar_exe_size = info->tar_offset_end - info->tar_offset_start;
	char buffer[4096];
	uint64_t bytes_remaining = tar_exe_size;
	while (bytes_remaining > 0) {
		size_t bytes_to_read = (bytes_remaining < sizeof(buffer)) ? bytes_remaining : sizeof(buffer);
		size_t bytes_read = fread(buffer, 1, bytes_to_read, fp);
		if (bytes_read == 0) {
			exit(EXIT_FAILURE);
		}
		fwrite(buffer, 1, bytes_read, out_fp);
		bytes_remaining -= bytes_read;
	}
	fclose(out_fp);
	fclose(fp);
	free(info);
	chmod(output_file, 0755);
}
void dump_origional_exe(const char *output_file)
{
	/*
	 * Dump the original executable from the SSFX master file.
	 */
	if (!self_is_valid_ssfx_master()) {
		printf("This executable is not a valid SSFX master file.\n");
		exit(EXIT_FAILURE);
	}
	struct ssfx_info_master *info = malloc(sizeof(struct ssfx_info_master));
	if (!info) {
		perror("Failed to allocate memory for ssfx_info_master");
		exit(EXIT_FAILURE);
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
	fseek(fp, -sizeof(struct ssfx_info_master), SEEK_END);
	fread(info, sizeof(struct ssfx_info_master), 1, fp);
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		printf("Invalid SSFX master info structure.\n");
		exit(EXIT_FAILURE);
	}
	FILE *out_fp = fopen(output_file, "wb");
	if (!out_fp) {
		perror("Failed to open output file for original executable");
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_SET);
	uint64_t original_exe_size = info->tar_offset_start - sizeof(info->splitter);
	char buffer[4096];
	uint64_t bytes_remaining = original_exe_size;
	while (bytes_remaining > 0) {
		size_t bytes_to_read = (bytes_remaining < sizeof(buffer)) ? bytes_remaining : sizeof(buffer);
		size_t bytes_read = fread(buffer, 1, bytes_to_read, fp);
		if (bytes_read == 0) {
			exit(EXIT_FAILURE);
		}
		fwrite(buffer, 1, bytes_read, out_fp);
		bytes_remaining -= bytes_read;
	}
	fclose(out_fp);
	fclose(fp);
	free(info);
	chmod(output_file, 0755);
}
void pack_ssfx_other(const char *output_file)
{
	dump_origional_exe("./origional_exe_dumped");
	FILE *fp_origional = fopen("./origional_exe_dumped", "rb");
	if (!fp_origional) {
		perror("Failed to open origional exe file");
		exit(EXIT_FAILURE);
	}
	remove(output_file);
	unlink(output_file);
	rmdir(output_file);
	FILE *fp_output = fopen(output_file, "wb");
	if (!fp_output) {
		perror("Failed to open output_file file");
		exit(EXIT_FAILURE);
	}
	uint8_t splitter[32];
	memset(splitter, 0, sizeof(splitter));
	strcpy((char *)splitter, SSFX_SPLITTER);
	FILE *splitter_fp = fmemopen(splitter, sizeof(splitter), "rb");
	fseek(fp_origional, 0, SEEK_SET);
	// Copy origional executable to output
	fseek(fp_origional, 0, SEEK_SET);
	append_file(fp_origional, fp_output);
	fclose(fp_origional);
	fseek(splitter_fp, 0, SEEK_SET);
	append_file(splitter_fp, fp_output);
	struct ssfx_info_other info;
	info.magic_start = SSFX_MAGIC_START;
	memset(info.splitter, 0, sizeof(info.splitter));
	strcpy((char *)info.splitter, SSFX_SPLITTER);
	info.magic_end = SSFX_MAGIC_END;
	FILE *info_fp = fmemopen(&info, sizeof(info), "rb");
	append_file(info_fp, fp_output);
	fclose(info_fp);
	fclose(fp_output);
	chmod(output_file, 0755);
	remove("./origional_exe_dumped");
}