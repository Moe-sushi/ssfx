//
//
#include "include/ssfx.h"
/*
void find_splitter_offsets(const struct ssfx_info_pack *info)
{
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint8_t splitter_check[sizeof(info->splitter)];
	memccpy(splitter_check, info->splitter, 0, sizeof(info->splitter));
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
	while (offset < file_size - sizeof(info->splitter)) {
		if (memcmp(file_buffer + offset, splitter_check, sizeof(info->splitter)) == 0) {
			printf("Found splitter at offset: %lu\n", offset);
			found_count++;
		}
		offset++;
	}
	free(file_buffer);
}

void verify_ssfx_info_pack_and_print(const struct ssfx_info_pack *info)
{
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		printf("Invalid SSFX info structure.\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Valid SSFX info structure detected.\n");
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (info->tar_offset_end > file_size || info->file_offset_end > file_size) {
		printf("SSFX info offsets exceed file size.\n");
		fclose(fp);
		exit(EXIT_FAILURE);
	}
	// goto tar offset start and verify splitter
	fseek(fp, info->tar_offset_start - sizeof(info->splitter), SEEK_SET);
	uint8_t splitter_check[sizeof(info->splitter)];
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		printf("Splitter verification failed at tar offset start.\n");
		fclose(fp);
		exit(EXIT_FAILURE);
	} else {
		printf("Splitter verification succeeded at tar offset start.\n");
	}
	// goto file offset start and verify splitter
	fseek(fp, 0, SEEK_SET);
	fseek(fp, info->file_offset_start - sizeof(info->splitter), SEEK_SET);
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		printf("Splitter verification failed at file offset start.\n");
		fclose(fp);
		exit(EXIT_FAILURE);
	} else {
		printf("Splitter verification succeeded at file offset start.\n");
	}
	// goto file end and verify splitter
	fseek(fp, 0, SEEK_SET);
	fseek(fp, info->file_offset_end, SEEK_SET);
	memset(splitter_check, 0, sizeof(splitter_check));
	fread(splitter_check, sizeof(info->splitter), 1, fp);
	if (memcmp(splitter_check, info->splitter, sizeof(info->splitter)) != 0) {
		printf("Splitter verification failed at file offset end.\n");
		fclose(fp);
		exit(EXIT_FAILURE);
	} else {
		printf("Splitter verification succeeded at file offset end.\n");
	}
	printf("All SSFX info verifications passed.\n");
	fclose(fp);
}
struct ssfx_info_pack *read_ssfx_info_pack(void)
{
	struct ssfx_info_pack *info = malloc(sizeof(struct ssfx_info_pack));
	if (!info) {
		perror("Failed to allocate memory for ssfx_info_pack");
		exit(EXIT_FAILURE);
	}
	FILE *fp = fopen("/proc/self/exe", "rb");
	if (!fp) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
	fseek(fp, -sizeof(struct ssfx_info_pack), SEEK_END);
	fread(info, sizeof(struct ssfx_info_pack), 1, fp);
	fclose(fp);
	return info;
}
void check_and_print_ssfx_info_pack(void)
{
	struct ssfx_info_pack *info = read_ssfx_info_pack();
	if (info->magic_start != SSFX_MAGIC_START || info->magic_end != SSFX_MAGIC_END) {
		printf("Invalid SSFX info structure.\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Valid SSFX info structure detected.\n");
	}
	printf("SSFX Information:\n");
	printf("  Tar Offset Start: %lu\n", info->tar_offset_start);
	printf("  Tar Offset End:   %lu\n", info->tar_offset_end);
	printf("  File Offset Start: %lu\n", info->file_offset_start);
	printf("  File Offset End:   %lu\n", info->file_offset_end);
	printf("  Splitter:         %s\n", info->splitter);
	printf("  Entrance Point:   %s\n", info->entrance_point);
	find_splitter_offsets(info);
	verify_ssfx_info_pack_and_print(info);
	free(info);
}
*/
int main(int argc, char *argv[])
{
	if (self_is_valid_ssfx_master()) {
		printf("This is a valid SSFX master file.\n");
		pack_ssfx_other("./ssfx_other_packed");
	} else if (self_is_valid_ssfx_pack()) {
		printf("This is a valid SSFX packed file.\n");
	} else if (self_is_valid_ssfx_other()) {
		printf("This is a valid SSFX other packed file.\n");
		return 0;
	} else {
		printf("This is a normal executable file.\n");
	}
	if (argc == 1) {
		if (self_is_valid_ssfx_master()) {
			dump_origional_exe("./origional_exe_dumped");
			dump_tar_exe("./ssfx_tmp_tar_exe");
			return 0;
		}
		if (!self_is_valid_ssfx_pack()) {
			printf("This executable is not a valid SSFX file.\n");
			return EXIT_FAILURE;
		}
		unpack_and_run_ssfx("./test");
	} else if (argc == 3) {
		pack_ssfx_master(argv[1], argv[2]);
	} else if (argc == 4) {
		pack_ssfx_file(argv[1], argv[2], argv[3]);
	} else {
		printf("Usage:\n");
		printf("  To unpack SSFX file: %s\n", argv[0]);
		printf("  To pack SSFX file: %s <tar_file> <output_file> <entrance_point>\n", argv[0]);
		return EXIT_FAILURE;
	}
	return 0;
}