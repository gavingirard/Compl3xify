# Compl3xify
This was a fun project that I did when I was younger to create a really ridiculous obfuscator for Python programs. In `samples/` there is a simple file `hex.py` and its obfuscated version `OBF_hex.py`. Included also is a deobfuscator which was used on `OBF_hex.py` to create `DEOBF_OBF_hex.py`. This program is not practical in any way and shouldn't be used for any sort of real world use, but it is fun and has a lot of weird features that make it pretty hard to crack without having access to the deobfuscation code.

The program has a few interesting features to make it secure:
- The hash of the output Python file is stored inside of the obfuscated program, and it will refuse to run if it is modified in any way to try and debug it
- It stores the strings for the original script's contents in the format of `[a-z0-9]{2}.[a-z...` which is hex codes with a bunch of substitutions
- It hides variable assignments inside of those script strings; for example, at the end of the program there is the run function `OBFUSCATED_NAME()`. However, if you try to see where that funciton name was used all you will find is it being set to `None`

Arguments for the obfuscator:

- `-f/-file <path>` - The target file to be obfuscated
- `-v/-verbose` - Run in verbose mode to give more information about what's going on
- `--rev` - Reverse the strings which are stored internally
- `--fh` - Add in fake dummy hashes to the part of the program which stores the actual hashes to make it more difficult to remove/modify the hash
- `-l/-length <length>` - Set the length of variable names; setting this too low will cause collisions
- `-g/-groupsize` - Size to use for ordinal groups in the obfuscation. Recommended to be >100 for decently sized scripts. For scripts >2000 lines, a group size of over 500 is almost a requirement
- `-seed <seed>` - Seed to use for the random number generator
- `--hashless` - If the program is being converted into an executable like an EXE, use this so it doesn't check its own hash
- `--varchars <chars>` - Characters to choose from for variable names

Arguments for the deobfuscator:

- `-f/-file <path>` - The obfuscated script to deobfuscate
