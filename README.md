# sebastian

A PE dumper and reconstructor targeting Hyperion-protected Roblox binaries. Forces decryption of encrypted code pages via `NtFlushInstructionCache` and rebuilds the import directory from memory.

## How it works

Hyperion encrypts code pages at rest and decrypts them on-demand when they're executed. `NtFlushInstructionCache` is hooked by Hyperion — calling it on an encrypted page triggers decryption before the flush completes. Sebastian exploits this by flushing every page in the executable's code sections, reading the decrypted bytes, and patching them over the encrypted disk image.

Data sections (`.rdata`, `.data`, `.reloc`) are also flushed the same way. Once readable, the import scanner walks every 8-byte aligned value in every readable section, matches addresses against the export tables of all loaded modules, and reconstructs a complete import directory in a new PE section.

## Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

## Usage
lucefdecryptor.exe [percentage]
- `percentage` — how much of the code section to decrypt (0-100, default 100)

The target process (`RobloxPlayerBeta.exe`) must be running. The dumped and reconstructed executable is saved as `dumped.exe` in the current directory.
