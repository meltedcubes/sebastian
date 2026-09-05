# Sebastian

A PE dumper and reconstructor for Hyperion-protected Windows binaries, aimed at RobloxPlayerBeta.exe. It forces Hyperion to decrypt its code pages in memory, copies the decrypted image to disk, repairs the section headers so the result is recognized as executable code, and rebuilds a complete import directory.

## Overview

Hyperion encrypts the code of Roblox at rest and decrypts pages on demand, just before they are executed. Static files expose almost nothing, and naive memory dumps still carry section headers that mislabel code as data.

Sebastian reverses that:

1. It opens the running Roblox process and loads its on-disk image.
2. For each page, it calls `NtFlushInstructionCache` with a range inside the module. The Hyperion hook is not installed, so on that call, a exception happens on the encrypted page, and hyperion decrypts the page before the flush completes.
3. The freshly decrypted page is read from memory and written back over the original encrypted bytes in the image buffer.
4. Each section whose pages are actually executable at runtime is marked as `CODE | EXECUTE | READ` in the output headers.
5. It scans every readable section for pointers into the export tables of the loaded modules, resolves the imports, and writes a fresh import directory into a new `.hetalia` section.
6. The result is saved as `dumped.exe`.

## Requirements

- The target process running (RobloxPlayerBeta.exe)
- Administrator rights to read and operate on the target process

## Build

Build from the source root with MinGW-w64 (64-bit):

```sh
g++ -std=c++20 -O2 -static -static-libgcc -static-libstdc++ main.cpp -o lucefdecryptor.exe
```

A CMake project is also included for Visual Studio or any generator that supports C++20.

## Usage

```sh
lucefdecryptor.exe [percentage]
```

- `percentage` (optional) - how much of the code section to decrypt, from 0 to 100. The default is 100.
- Values outside the valid range fall back to the default.
- The target process must already be running - the tool attaches to it rather than launching it.

Example:

```sh
lucefdecryptor.exe 100
```

On success, `dumped.exe` appears in the current working directory.

## Using the dump

1. Open `dumped.exe` in IDA or your disassembler of choice.
2. Confirm the code segments are now executable sections (`.text` and friends) - the repaired headers are what keep them from loading as raw data.
3. If IDA left large regions undefined, select the segment and force a disassembly pass (`Make Code`). Undefined bytes in those regions mean the page in question was never decrypted by Hyperion during the session, not a failure of the dump itself.

## Limitations

- Pages that Hyperion never decrypts at runtime stay encrypted in the dump. They are reported as dead pages at the end of the run. Moving around in-game before dumping, or dumping at 100%, reduces them.
- Import detection matches 8-byte values against known module exports. False positives are unlikely but possible.

## Credits

Written by kellan (@kellanvisor on Discord).

## License

MIT.
