---
title: "Seeing the JIT: Building hsdis on Apple Silicon Without the OpenJDK Build System"
description: "How to compile the HotSpot Disassembler plugin for JVM performance analysis on M1/M2/M3/M4 Macs, without fighting the OpenJDK build system."
date: 2026-01-18
categories: [Tooling, Performance]
tags: [jvm, hsdis, macos, apple-silicon, profiling, assembly]
image:
  path: /assets/images/hsdis-header.jpg
  alt: "Photo by Florian Olivo on Unsplash"
---

## TL;DR

Can't see JIT assembly on your Mac? Install Capstone (`brew install capstone`), clone OpenJDK, and compile hsdis with a single direct `clang` invocation. Skip the painful OpenJDK build system entirely. Full one-liner at the [bottom](#quick-reference).

## What Happens When You Ask the JVM for Assembly?

You're profiling a hot loop. The flamegraph points to a method, but you need to see *what the JIT actually generated*. Let's try the obvious thing:

```bash
java -XX:+UnlockDiagnosticVMOptions -XX:+PrintAssembly -version
```

And we get:

```
0x000000010eed8180: <unknown>
0x000000010eed8184: <unknown>
0x000000010eed8188: <unknown>
```

Not helpful. The JVM is telling you it doesn't know how to disassemble its own machine code. It needs a plugin called **hsdis**, and it's not included by default.

If you've spent hours trying to build hsdis on your M1/M2/M3/M4 Mac only to hit cryptic errors about Metal shaders (yes, really), you're not alone. This post shows you a faster way.

## What is hsdis?

**hsdis** (HotSpot Disassembler) is a small plugin library (~50KB) that teaches the JVM how to translate machine code back into human-readable assembly.

![How hsdis works: JVM passes machine code through hsdis to produce readable assembly](/assets/images/hsdis-architecture.svg){: .align-center}

With it installed, `-XX:+PrintAssembly` transforms from useless to invaluable:

```text
0x000000010eed8180:   ldr     w8, [x1, #8]      ; load array length
0x000000010eed8184:   cmp     w9, w8            ; bounds check
0x000000010eed8188:   b.eq    #0x10eed81c0      ; branch if equal
```

Now you can actually see:
- Whether your loop got vectorized (look for SIMD instructions like `ld1`, `fmla`)
- How the JIT optimized your code
- Why that "simple" method is slower than expected
- Whether bounds checks were eliminated

This is essential for serious performance work, especially when benchmarking with JMH.

## Why Is This So Hard on Apple Silicon?

Building hsdis on Apple Silicon presents a few speed bumps:

| Challenge | Details |
|-----------|---------|
| **Architecture** | ARM64 (aarch64), not x86_64 |
| **Library naming** | `hsdis-aarch64.dylib` not `hsdis-amd64.dylib` |
| **Build system** | OpenJDK's configure demands Xcode's Metal tools |
| **Backend choice** | binutils, Capstone, or LLVM? |

The official approach (`bash configure && make build-hsdis`) often fails with errors like:

```
configure: error: XCode tool 'metallib' neither found in path nor with xcrun
```

Metal shaders? For a disassembler? The OpenJDK build system is designed to build the *entire JDK*, including macOS-specific UI components. Even with full Xcode installed, you might still hit this wall.

There's a better way.

## Can We Just Compile It Directly?

Here's the insight: **hsdis is just a thin wrapper around a disassembly library**. The source is a single C file. Let's see if we can compile it directly with `clang`, bypassing the entire OpenJDK build system.

We'll use [Capstone](https://www.capstone-engine.org/), a lightweight, multi-architecture disassembly framework. Let's try it.

### Prerequisites

Since we're bypassing the OpenJDK build system, we only need a C compiler and the disassembly library itself:

```bash
# Install Xcode Command Line Tools (if not already installed)
xcode-select --install

# Install Capstone disassembly framework
brew install capstone

# Verify installation
ls /opt/homebrew/opt/capstone/lib/libcapstone.dylib
```

That's it. No full Xcode, no Metal tools, no autoconf nightmares.

### Step 1: Get the hsdis Source

Let's grab the source. We only need a few files from OpenJDK, about 3 files totaling a few KB. The easiest way is a shallow clone:

```bash
# Shallow clone just what we need (this downloads ~200MB, not the full 1GB+)
git clone --depth 1 --branch jdk-21+35 \
    https://github.com/openjdk/jdk.git ~/workspace/openjdk-hsdis

# The source files we need are here:
ls ~/workspace/openjdk-hsdis/src/utils/hsdis/
# capstone/  hsdis.h  README.md  ...
```

> **Tip**: You can use any JDK version branch (jdk-17, jdk-21, jdk-22, etc.). The hsdis source is stable across versions.

### Step 2: Compile hsdis

Let's see if this actually works. One command, no build system:

```bash
cd ~/workspace/openjdk-hsdis
mkdir -p build/hsdis

clang -dynamiclib \
    -arch arm64 \
    -DCAPSTONE_ARCH=CS_ARCH_ARM64 \
    -DCAPSTONE_MODE=CS_MODE_ARM \
    -I src/utils/hsdis \
    -I /opt/homebrew/opt/capstone/include/capstone \
    -L /opt/homebrew/opt/capstone/lib \
    -lcapstone \
    -o build/hsdis/hsdis-aarch64.dylib \
    src/utils/hsdis/capstone/hsdis-capstone.c
```

Let's break down what each flag does:

| Flag | Purpose |
|------|---------|
| `-dynamiclib` | Create a shared library (`.dylib` on macOS) |
| `-arch arm64` | Target Apple Silicon architecture |
| `-DCAPSTONE_ARCH=CS_ARCH_ARM64` | Tell Capstone we're disassembling ARM64 code |
| `-DCAPSTONE_MODE=CS_MODE_ARM` | Set the ARM instruction mode |
| `-I .../capstone` | Include path for Capstone headers |
| `-L .../lib -lcapstone` | Link against the Capstone library |

The compilation finishes almost instantly.

### Step 3: Did It Work?

Let's verify we built the right thing:

```bash
# Check the library architecture
file build/hsdis/hsdis-aarch64.dylib
# Mach-O 64-bit dynamically linked shared library arm64

# Verify the magic symbol exists
nm -gU build/hsdis/hsdis-aarch64.dylib | grep decode
# 0000000000000500 T _decode_instructions_virtual
```

The `_decode_instructions_virtual` symbol is the entry point the JVM looks for. If you see it, you're golden.

### Step 4: Does the JVM See It Now?

Copy the library to where the JVM can find it:

```bash
# Option 1: Project-specific location (recommended for development)
mkdir -p ~/workspace/benchmarks/tools/hsdis
cp build/hsdis/hsdis-aarch64.dylib ~/workspace/benchmarks/tools/hsdis/

# Option 2: System-wide installation (available to all Java processes)
sudo cp build/hsdis/hsdis-aarch64.dylib $JAVA_HOME/lib/server/
```

If you switch JDK versions later, you may need to copy the library to the new JDK's `lib/server/` directory as well.

Now let's run the same command that failed before:

```bash
# If using project-specific location, set the library path
DYLD_LIBRARY_PATH=~/workspace/benchmarks/tools/hsdis \
java -XX:+UnlockDiagnosticVMOptions \
     -XX:+PrintAssembly \
     -version 2>&1 | head -50
```

And now we get actual ARM64 assembly:

```
[Entry Point]
  # {method} '<init>' '()V' in 'java/lang/Object'
  0x000000010eed8180:   ldr     w8, [x1, #8]      ; load from heap
  0x000000010eed8184:   cmp     w9, w8            ; compare registers
  0x000000010eed8188:   b.eq    #0x10eed81c0      ; conditional branch
  0x000000010eed818c:   b       #0x116447e80      ; {runtime_call ic_miss_stub}
```

That's more like it. We can see the actual instructions the JIT generated: loads, compares, branches. The `{runtime_call ic_miss_stub}` annotation tells us this branch goes to the inline cache miss handler, useful context the JVM provides automatically.

## What About Intel Macs?

Intel Macs are increasingly rare, but if you're still on one, the process is nearly identical with different architecture flags:

```bash
clang -dynamiclib \
    -arch x86_64 \
    -DCAPSTONE_ARCH=CS_ARCH_X86 \
    -DCAPSTONE_MODE=CS_MODE_64 \
    -I src/utils/hsdis \
    -I /usr/local/opt/capstone/include/capstone \
    -L /usr/local/opt/capstone/lib \
    -lcapstone \
    -o build/hsdis/hsdis-amd64.dylib \
    src/utils/hsdis/capstone/hsdis-capstone.c
```

Key differences:
- `-arch x86_64` instead of `arm64`
- `CS_ARCH_X86` and `CS_MODE_64` for x86_64 disassembly
- Output file is `hsdis-amd64.dylib` (the JVM expects this exact name)
- Homebrew path is `/usr/local/opt/` on Intel Macs

## Troubleshooting

### "Could not load hsdis-aarch64.dylib"

The JVM can't find the library. Fix it by either:
1. Copying to `$JAVA_HOME/lib/server/` (no env var needed)
2. Setting `DYLD_LIBRARY_PATH` to include the directory containing the library

### No assembly output, just addresses

The library is loaded but not working. Check:
- Architecture matches your JVM (`arm64` vs `x86_64`)
- Capstone library is accessible at runtime (not just headers)
- Try running with `-Xlog:os+container` to see loading details

### Build fails with "capstone.h not found"

The include path needs to point to the directory *containing* `capstone.h`. On Apple Silicon:
```bash
# Headers are here (note the capstone subdirectory):
ls /opt/homebrew/opt/capstone/include/capstone/capstone.h
```

### "Undefined symbols: _cs_open"

The Capstone library isn't being linked. Make sure:
- `-L` points to the directory containing `libcapstone.dylib`
- `-lcapstone` is present in the command

## Why Not Just Use the Official Build?

The OpenJDK build system (`configure && make build-hsdis`) is comprehensive. It's designed to build the *entire JDK*. On macOS, this means requiring:

- Full Xcode installation (not just Command Line Tools)
- Metal shader compiler (`metal`, `metallib`)
- Autoconf and various other tools
- Patience

For a ~50KB shared library with one source file, this is overkill. The manual compilation approach:

- Compiles in seconds rather than requiring hours of setup
- Works with just Command Line Tools
- Produces an equivalent functional binary
- Actually works on Apple Silicon without Metal workarounds

## What Can We Do With This?

Once hsdis is installed, JMH's `perfasm` profiler becomes available. Let's see what it gives us:

```bash
java -jar benchmarks.jar -prof perfasm MyBenchmark
```

```
....[Hottest Region 1]..............................................................
c2, level 4, com.example.MyBenchmark::hotLoop, version 2, compile id 1042

                  0x00000001082d4a80:   ldr     w10, [x11, #12]     ; load array.length
                  0x00000001082d4a84:   cmp     w12, w10            ; bounds check
  2.31%           0x00000001082d4a88:   b.hs    0x1082d4b20         ; deopt if out of bounds
                  0x00000001082d4a8c:   add     x13, x11, w12, sxtw #2
 34.82%    ↗      0x00000001082d4a90:   ldr     s0, [x13, #16]      ; load array[i]
 28.91%    │      0x00000001082d4a94:   fadd    s0, s0, s1          ; sum += array[i]
  2.47%    │      0x00000001082d4a98:   add     w12, w12, #1        ; i++
 31.22%    │      0x00000001082d4a9c:   cmp     w12, w10            ; i < length?
           ╰      0x00000001082d4aa0:   b.lt    0x1082d4a90         ; loop back
```

Now we're getting somewhere. The percentages on the left show where cycles are spent. This loop is spending ~35% on the load, ~29% on the add, and ~31% on the loop comparison. The bounds check (`b.hs`) is outside the hot path: the JIT hoisted it.

Combined with async-profiler's flamegraphs, you have everything you need to understand what the JVM is actually doing with your code.

## Conclusion

Building hsdis on macOS Apple Silicon doesn't have to be a multi-hour ordeal. By understanding what hsdis actually is (a small shim that calls Capstone) we can compile it directly and skip the OpenJDK build system entirely.

Now go see what your JIT is really doing with that hot loop.

## Quick Reference

```bash
# Complete one-liner for Apple Silicon (M1/M2/M3/M4)
brew install capstone && \
git clone --depth 1 --branch jdk-21+35 https://github.com/openjdk/jdk.git /tmp/jdk && \
clang -dynamiclib -arch arm64 \
    -DCAPSTONE_ARCH=CS_ARCH_ARM64 -DCAPSTONE_MODE=CS_MODE_ARM \
    -I /tmp/jdk/src/utils/hsdis \
    -I /opt/homebrew/opt/capstone/include/capstone \
    -L /opt/homebrew/opt/capstone/lib -lcapstone \
    -o hsdis-aarch64.dylib \
    /tmp/jdk/src/utils/hsdis/capstone/hsdis-capstone.c && \
sudo cp hsdis-aarch64.dylib $JAVA_HOME/lib/server/
```

## Resources

- [OpenJDK hsdis source](https://github.com/openjdk/jdk/tree/master/src/utils/hsdis): The official source files
- [Capstone Engine](https://www.capstone-engine.org/): Multi-architecture disassembly framework
- [HotSpot PrintAssembly Wiki](https://wiki.openjdk.org/display/HotSpot/PrintAssembly): Official documentation
- [JMH Profilers](https://github.com/openjdk/jmh/blob/master/jmh-core/src/main/java/org/openjdk/jmh/profile/): Using hsdis with JMH benchmarks
- [Nitsan Wakart's Blog](https://psy-lob-saw.blogspot.com/): Deep dives into JVM performance and assembly analysis
