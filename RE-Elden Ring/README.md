# RE?Elden Ring — Memory Scanner (Educational)

A small Windows C++ (C++14) project that demonstrates reading and updating another process's memory. It was created as an educational reverse?engineering exercise (inspired by tools like Cheat Engine) to explore how Elden Ring stores in?game "ruins" (coins) values.

This repository contains a simple memory scanner/updater implemented with WinAPI (`VirtualQueryEx`, `ReadProcessMemory`, `WriteProcessMemory`) and multithreaded scanning using `std::thread`.

---

## Important note
This project is intended for learning, research, and reverse?engineering practice only. Modifying or distributing cheats for games is unethical and may violate the game's terms of service and local law. Use this code responsibly and only on processes you own or have permission to analyze.

---

## Features
- Enumerates processes to find a target executable by name.
- Scans readable committed memory regions for a32?bit integer value.
- Supports iterative narrowing: use previous found addresses to refine search results.
- Multi?threaded scanning using `std::thread` with round?robin partitioning of memory regions.
- Writes a new32?bit integer value to found addresses (requires appropriate privileges).
- Simple progress display and reporting of successes/failures for writes.

---

## Requirements
- Windows (reads/writes Win process memory)
- Visual Studio (recommended) or an MSVC toolchain supporting C++14
- Administrator privileges may be required to open/write some processes

---

## Build
1. Open the solution or project in Visual Studio (the `RE?Elden Ring` project).
2. Make sure the platform is x86 or x64 to match the target process architecture.
3. Set the C++ language standard to C++14 (Project Properties -> C/C++ -> Language).
4. Build the project.

Alternatively, if you have MSVC command line tools, build with `cl` and link as usual for a Win32 console program.

---

## Run / Usage
1. Run the compiled executable as Administrator if you need elevated access.
2. It targets `eldenring.exe` by default (see `main.cpp`); modify the `targetProcessName` variable to point to a different process if needed.
3. Enter an integer value to search for when prompted. The first run scans the whole process memory (may take time).
4. The program lists found addresses. You can either:
 - Continue scanning with a new value (this will only check the previously found addresses and narrow results), or
 - Enter a new value to write to all found addresses (use with extreme caution), or
 - Exit.

---

## Performance tuning
- Scanning stride: the current scanner checks every byte offset. If you expect aligned32?bit integers, change the inner loop to increment `j` by `sizeof(int)` instead of `1` to drastically reduce work.
- Chunk size: the code reads memory in4 MB chunks (`maxChunk`). You can reduce or increase this for your environment.
- Threads: the program uses `std::thread::hardware_concurrency()` threads by default. You can change the thread count in `ScanMemory` if you want to limit CPU usage.

---

## Code files of interest
- `main.cpp` — main program: process lookup, memory scanning, and update logic.

Use backticks around file and function names when referring to them in code edits.

---

## Safety and troubleshooting
- `OpenProcess` can fail if the process is protected or you lack privileges. Run as Administrator.
- Reading/writing arbitrary memory can crash the target process; test on non?critical processes.
- Some memory regions are guarded or inaccessible. The scanner skips regions with `PAGE_GUARD` and `PAGE_NOACCESS` protections.

---

## License
This project is provided for educational purposes. No license is included — add one if you plan to publish or share broadly.

---

If you want, I can:
- Add a simple command?line interface to pass the target process name and thread/chunk options,
- Change the scanner to only check aligned integers for a big speedup,
- Add logging or a dry?run mode to safely test write operations.

Which of those would you like next?