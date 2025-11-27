//
//
#include "include/ssfx.h"
int main(int argc, char *argv[])
{
	// Get file size of /usr/bin/tar
	FILE *fp = fopen("/usr/bin/tar", "rb");
	if (fp == NULL) {
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	uint64_t file_size = ftell(fp);
	fclose(fp);
	ssfx_dump_a_file_to_disk("/usr/bin/tar", "tar.dump", 0, file_size);
	int fd = ssfx_load_a_elf_to_memory("/usr/bin/tar", 0, file_size);
	if (fd == -1) {
		return -1;
	}
	if (ssfx_verify_ssfx_info(NULL) != 0) {
		printf("No SSFX info found in self executable.\n");
		struct ssfx_pack pack;
		ssfx_init_ssfx_pack(&pack);
		pack.output_path = "ssfx_other_packed_0";
		pack.ssfx_id = 7;
		ssfx_pack_ssfx(&pack);
		pack.output_path = "ssfx_other_packed";
		pack.file_0_path = "/usr/bin/tar";
		pack.file_0_id = 1;
		pack.file_0_comment = "tar";
		pack.file_1_path = "/usr/bin/ls";
		pack.file_1_id = 2;
		pack.file_1_comment = "ls";
		pack.file_2_path = "/usr/bin/cat";
		pack.file_2_id = 3;
		pack.file_2_comment = "cat";
		pack.ssfx_id = 42;
		pack.ssfx_comment = "xxxxxx";
		if (ssfx_pack_ssfx(&pack) != 0) {
			printf("Failed to pack ssfx_other_packed\n");
			return -1;
		}
	} else {
		ssfx_print_ssfx_info(NULL);
		ssfx_find_and_print_splitter_offsets(NULL);
		struct ssfx_info info = ssfx_get_ssfx_info(NULL);
		ssfx_dump_a_file_to_disk(NULL, "file_0_dumped", info.file_0_start, info.file_0_end);
		ssfx_dump_a_file_to_disk(NULL, "file_1_dumped", info.file_1_start, info.file_1_end);
		ssfx_dump_a_file_to_disk(NULL, "file_2_dumped", info.file_2_start, info.file_2_end);
	}
	// Fork and execve
	pid_t pid = fork();
	if (pid == -1) {
		close(fd);
		return -1;
	} else if (pid == 0) {
		// Child process
		char fd_path[64];
		sprintf(fd_path, "/proc/self/fd/%d", fd);
		char *const argv[] = { fd_path, NULL };
		char *const envp[] = { NULL };
		execve("/usr/bin/tar", argv, envp);
		// If execve fails
		close(fd);
		exit(-1);
	} else {
		// Parent process
		int status;
		waitpid(pid, &status, 0);
		close(fd);
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		} else {
			return -1;
		}
	}
}