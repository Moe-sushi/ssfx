# About:
ssfx (Simple Static SFX) is a lightweight c lib for creating self-extracting static archives.      
It allows you to bundle multiple files into a single executable file that can extract and run the contained files without requiring any external dependencies.      
# Features:
- Load elf from memfd.
- Pack max 5 files into a single executable.
- 512 bytes comment for each file.
- 512 bytes top-level comment.