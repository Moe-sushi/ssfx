# About:
ssfx (Simple Static SFX) is a lightweight c lib for creating self-extracting static archives.      
It allows you to bundle multiple files into a single executable file that can extract and run the contained files without requiring any external dependencies.      
# Features:
- Load elf from memfd.
- Pack max 5 files and self executable into single executable.
- Each file and self executable can have a uint64_t ID and 512 bytes comment.