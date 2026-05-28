# Parasitic ELF Infection of SCOP and PIE Binaries

This project implements a modern **parasitic infector** for Linux ELF binaries that are compiled as **Position Independent Executables (PIE)** and/or use **Secure Code Partitioning (SCOP)**. The infector inserts a position‑independent payload into the target binary, redirects execution by hijacking the `__libc_start_main` arguments, and ensures the original program runs transparently after the payload finishes.

The techniques used are based on the paper **"20:07 Modern ELF Infection Techniques of SCOP Binaries"** by Ryan "ElfMaster" O’Neill, specifically the **Ultimate Text Infection (UTI)** method for SCOP binaries.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
  - [Detecting SCOP Binaries](#detecting-scop-binaries)
  - [Ultimate Text Infection (UTI)](#ultimate-text-infection-uti)
  - [Hijacking `__libc_start_main`](#hijacking-__libc_start_main)
  - [Parasite Payload](#parasite-payload)
- [Dependencies](#dependencies)
- [Compilation](#compilation)
- [Usage](#usage)
- [References](#references)

---

## Overview

Traditional ELF infection techniques (e.g., Silvio Cesare’s text segment padding) rely on fixed addresses and a single `PT_LOAD` segment for executable code. Modern Linux distributions now enable **SCOP**, which splits the text image into three `PT_LOAD` segments:
1. Read‑only (`PF_R`)
2. Read+execute (`PF_R | PF_X`)
3. Read‑only (`PF_R`)

Additionally, **PIE** (Position Independent Executable) is enabled by default, randomising the base address at runtime. These changes break classic infection methods.

Our infector:
1. **Detects** whether the target is a SCOP binary.
2. **Injects** a parasite into the large slack space that naturally exists between the second (`PF_R|PF_X`) and third (`PF_R`) `PT_LOAD` segments (the **UTI** method).
3. **Redirects** control flow by patching the `LEA` instruction found at the original entry point – the instruction that loads the address of `main` for `__libc_start_main`. The patch points to the injected parasite.
4. The **parasite** (written in x86‑64 assembly) prints a message, then uses a runtime‑computed delta to jump back to the original `main` function.

No system configuration files or startup directories are modified – persistence is achieved directly in the binary.

---

## How It Works

### Detecting SCOP Binaries

The function `validate_scop_compliance_and_extract_scop_headers()` checks the first three `PT_LOAD` segments:
- Segment 0: `PF_R`
- Segment 1: `PF_R | PF_X`
- Segment 2: `PF_R`

If this pattern is found, the binary is considered SCOP‑compliant and the program header details are stored.

### Ultimate Text Infection (UTI)

For SCOP binaries, the second `PT_LOAD` segment (executable) is followed by a large gap on disk before the third `PT_LOAD` segment. The slack space is calculated as:

slack = PT_LOAD[2].p_offset - (PT_LOAD[1].p_offset + PT_LOAD[1].p_filesz)


This gap is often **> 2 MB**, large enough for any realistic parasite. The infector:
- Expands `PT_LOAD[1].p_filesz` and `PT_LOAD[1].p_memsz` by the parasite size.
- Adjusts the corresponding section header (typically `.fini`) to keep the section view consistent.
- Writes the parasite code directly into the slack space at offset `PT_LOAD[1].p_offset + PT_LOAD[1].p_filesz`.

No shifting of subsequent segments is required, because the third segment’s offset is already far enough ahead.

### Hijacking `__libc_start_main`

In PIE binaries, the entry point (`e_entry`) points to `_start`, which eventually calls `__libc_start_main`. The arguments to `__libc_start_main` include a pointer to the `main` function. A typical `_start` prologue contains an instruction like:

lea 0x2e(%rip),%rdi # loads address of main


Our infector:
1. Extracts the first 40 bytes at the entry point (from the target binary).
2. Uses **Capstone** to find the `lea` instruction that references `rip` – this is the one loading `main`.
3. Computes the **new displacement** so that the same `lea` instruction now points to the injected parasite’s virtual address.
4. Patches the displacement in the target binary.

The parasite begins execution **after** the C library has initialised, with the original `main` address still available on the stack or in registers. This avoids issues with unresolved dynamic symbols.

### Parasite Payload

The assembly file `parasite.s`:
- Preserves all registers that may be used by `__libc_start_main` (`rdi`, `rsi`, `rdx`, `rbx`, `rbp`, `r12`–`r15`).
- Performs a simple payload: `write(1, "absurd\n", 7)`.
- Contains a `get_rip` function that obtains the current instruction pointer at runtime (position‑independent).
- Adds a pre‑computed `delta` to this pointer to obtain the original `main` address.
- Restores registers and jumps to `main`.

The `delta` value is calculated by the infector as:

delta = original_main_vaddr - get_rip_vaddr

and patched into the parasite’s `.quad 0x0` placeholder at the very end of the parasite.

---

## Dependencies

Build tools:
- `gcc`
- `make` (optional)
- `as` (GNU assembler)
- `objcopy`

Libraries:
- `libelf` (ELF manipulation)
- `libcapstone` (disassembly)

On Debian/Ubuntu, install with:
```bash
sudo apt install binutils gcc libelf-dev libcapstone-dev
```


## Compilation

**1. Build the Parasite**

```bash
as parasite.s -o parasite.o
objcopy -O binary -j .text parasite.o parasite.bin
```

This produces `parasite.bin` – a raw binary blob of the parasite code.

**2. Build the Infector**

```bash
gcc -Wall -o infector infector.c -lelf -lcapstone
```

## Usage

```bash
./infector <target_elf>
```

**Important:** The target must be a **SCOP/PIE** ELF binary (e.g., compiled with gcc -fPIC -pie). Many modern system binaries (like /bin/ls) are SCOP‑compliant.

The infector modifies the binary in‑place. Always work on a copy.

**Example:**

```bash
cp /bin/ls ./ls_patched
./infector ./ls_patched
./ls_patched      # will print "absurd\n" then behave like normal ls
```

## References

* Ryan “ElfMaster” O’Neill, “20:07 Modern ELF Infection Techniques of SCOP Binaries”.
* Silvio Cesare, “Unix ELF Parasites and Virus” (1998).