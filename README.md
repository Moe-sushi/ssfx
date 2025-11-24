# WIP:
Not very stable yet.      
# About:
ssfx (Simple Static SFX) is a lightweight c lib for creating self-extracting static archives.      
# Dependencies:
It need a static gnutar, for unpacking the archive.

# Stage:
## Stage 0:
Origional executable, can pack itself with tar executable, then it's at stage 1.

## Stage 1:
ssfx master, can dump itself or tar executable, and can also pack itself and a .tar archive into a stage 2 ssfx executable archive.

## Stage 2:
ssfx pack, can dump tar executable and unpack the embedded .tar archive, then exec the entrypoint of the unpacked archive.

## Stage 114:
ssfx can also append a mark to the executable itself, this is not used for self-extracting features, but you can use it to detect that your executable is in a special stat, so that you can do something special in your code.