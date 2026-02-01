---
title: "Seeing the JIT: Making Java's Machine Code Visible on Apple Silicon"
description: "Making HotSpot's JIT-generated machine code observable on Apple Silicon for low-level JVM performance analysis, using hsdis and Capstone."
date: 2026-01-18
categories: [Internals, Performance]
tags: [jvm, hsdis, macos, apple-silicon, profiling, assembly]
image:
  path: /assets/images/hsdis-header.jpg
  alt: "Photo by Florian Olivo on Unsplash"
---

## TL;DR

The JVM can show you the actual machine code the JIT generates, but this requires `hsdis`, a small disassembler plugin that is not bundled by default.

This post shows how to make HotSpot's JIT-generated machine code observable on Apple Silicon by satisfying the JVM's minimal `hsdis` plugin contract directly. This enables low-level JVM performance analysis and tools like JMH's perfasm profiler without relying on the full OpenJDK build system.

## What if `hsdis` Is Missing?

Say you're profiling a hot loop. The flamegraph points to a method, but you need to see *what the JIT actually generated*. The JVM has a diagnostic flag for this:

```bash
java -XX:+UnlockDiagnosticVMOptions -XX:+PrintAssembly -version
```

And we get:

```
0x000000010eed8180: <unknown>
0x000000010eed8184: <unknown>
0x000000010eed8188: <unknown>
```

Not helpful. The JVM is telling you it doesn't know how to disassemble its own machine code. It needs a plugin called **`hsdis`**, and it's not included by default.

If you've spent hours trying to build `hsdis` on your Mac only to hit cryptic errors about Metal shaders (yes, really), you're not alone. There's a simpler path that reveals what `hsdis` actually is.

## What is `hsdis`?

**`hsdis`** (HotSpot Disassembler) is a small plugin library (~50KB) that teaches the JVM how to translate machine code back into human-readable assembly.

![How hsdis works: JVM passes machine code through hsdis to produce readable assembly](/assets/images/hsdis-architecture.svg){: .align-center}

With it installed, `-XX:+PrintAssembly` transforms from useless to invaluable:

```text
0x000000010eed8180:   ldr     w8, [x1, #8]      ; load array length
0x000000010eed8184:   cmp     w9, w8            ; bounds check
0x000000010eed8188:   b.eq    #0x10eed81c0      ; branch if equal
```

With this visibility, you can answer questions that are otherwise guesswork. You can tell whether the JIT vectorized a loop by looking for SIMD instructions like `ld1` and `fmla`, confirm that bounds checks were eliminated, identify which instructions dominate the hot path, and understand why a "simple" method is slower than expected. This is essential for serious performance work, especially when benchmarking with JMH.

## What Does the JVM Actually Expect?

Not much. The requirements for `hsdis` are minimal: a shared library that exports `decode_instructions_virtual` and is discoverable via `$JAVA_HOME/lib/server/` or `java.library.path`. That's the entire contract, and it applies to any platform where HotSpot runs. The complexity comes from the official build system, not from what HotSpot actually expects.

> The JVM doesn't care *how* the plugin was built. It loads a shared library, looks up one symbol, and calls it. Everything else, the build system, the backend choice, the configure scripts, is incidental complexity.
{: .prompt-tip }

Building `hsdis` on Apple Silicon through the standard OpenJDK build presents several challenges. The target architecture is ARM64 (aarch64) rather than x86_64, the library must be named `hsdis-aarch64.dylib` instead of `hsdis-amd64.dylib`, and you need to choose between three disassembly backends ([binutils](https://www.gnu.org/software/binutils/), [Capstone](https://www.capstone-engine.org/), or [LLVM](https://llvm.org/)). On top of that, OpenJDK's `configure` demands Xcode's Metal tools, which have nothing to do with disassembly.

The official approach (`bash configure && make build-hsdis`) often fails with errors like:

```
configure: error: XCode tool 'metallib' neither found in path nor with xcrun
```

Metal shaders[^metal]? For a disassembler? The OpenJDK build system is designed to build the *entire JDK*, including macOS-specific UI components. Even with full Xcode installed, you might still hit this wall.

Understanding what the JVM actually requires suggests a simpler approach.

## Other Ways to Satisfy the JVM Contract?

Yes. The key insight is that **`hsdis` is just a thin wrapper around a disassembly library**. The Capstone-based implementation is essentially a single C translation unit plus a shared header. The JVM doesn't care how you build it, only that the resulting library exports the right symbol.

> The entire Capstone-based `hsdis` implementation is a single C file and a shared header. The OpenJDK build system wraps this in thousands of lines of configure scripts, but the actual work is one `clang` invocation away.
{: .prompt-tip }

This means we can compile it directly with `clang`, bypassing the entire OpenJDK build system and demonstrating what the JVM actually requires.

The disassembly backend we'll use is [Capstone](https://www.capstone-engine.org/), a lightweight, multi-architecture disassembly framework.

### Minimal Dependencies

To satisfy the contract directly, only two things are needed: a C compiler and the Capstone disassembly library:

```bash
# Install Xcode Command Line Tools (if not already installed)
xcode-select --install

# Install Capstone disassembly framework
brew install capstone

# Verify installation
ls /opt/homebrew/opt/capstone/lib/libcapstone.dylib
```

That's it. No full Xcode, no Metal tools, no autoconf nightmares.

### The Source

The `hsdis` source lives in the OpenJDK repository. The relevant files total a few KB, so a shallow clone[^shallow-clone] is sufficient:

```bash
# Shallow clone just what we need (this downloads ~200MB, not the full 1GB+)
git clone --depth 1 --branch jdk-21+35 \
    https://github.com/openjdk/jdk.git ~/workspace/openjdk-hsdis

# The source files we need are here:
ls ~/workspace/openjdk-hsdis/src/utils/hsdis/
# capstone/  hsdis.h  README.md  ...
```

> **Tip**: You can use any JDK version branch (jdk-17, jdk-21, jdk-22, etc.). The `hsdis` source is stable across versions.

### Building the Library

With the source and Capstone in place, a single `clang` invocation produces what the JVM expects:

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

Each flag addresses a specific part of the contract:

| Flag | Purpose |
|------|---------|
| `-dynamiclib` | Create a shared library (`.dylib` on macOS) |
| `-arch arm64` | Target Apple Silicon architecture |
| `-DCAPSTONE_ARCH=CS_ARCH_ARM64` | Tell Capstone we're disassembling ARM64 code |
| `-DCAPSTONE_MODE=CS_MODE_ARM` | Set the ARM instruction mode |
| `-I .../capstone` | Include path for Capstone headers |
| `-L .../lib -lcapstone` | Link against the Capstone library |

The compilation finishes almost instantly.

### Verifying the Contract

The resulting library must be a 64-bit ARM shared object exporting the symbol the JVM expects:

```bash
# Check the library architecture
file build/hsdis/hsdis-aarch64.dylib
# Mach-O 64-bit dynamically linked shared library arm64

# Verify the magic symbol exists
nm -gU build/hsdis/hsdis-aarch64.dylib | grep decode
# 0000000000000500 T _decode_instructions_virtual
```

The `_decode_instructions_virtual` symbol is the JVM's entry point into the plugin. If it's present, the contract is satisfied.

### Plugin Placement

The JVM searches for `hsdis` in specific locations. The library can be placed either alongside a project or system-wide:

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

That's more like it. We can see the actual instructions the JIT generated: loads, compares, branches. The `{runtime_call ic_miss_stub}` annotation tells us this branch goes to the inline cache miss handler[^inline-cache], useful context the JVM provides automatically.

## What About Intel Macs?

For completeness, the same approach applies to Intel Macs with different architecture flags:

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

The architecture flag changes to `-arch x86_64`, Capstone uses `CS_ARCH_X86` and `CS_MODE_64` for x86_64 disassembly, and the output file must be named `hsdis-amd64.dylib` since the JVM expects this exact name. On Intel Macs, Homebrew installs to `/usr/local/opt/` rather than `/opt/homebrew/opt/`.

## Troubleshooting

### "Could not load hsdis-aarch64.dylib"

The JVM can't find the library. The simplest fix is copying it to `$JAVA_HOME/lib/server/`, which requires no environment variables. Alternatively, set `DYLD_LIBRARY_PATH`[^dyld] to include the directory containing the library.

### "No assembly output, just addresses"

The library is loaded but not working. Make sure the architecture matches your JVM (`arm64` vs `x86_64`) and that the Capstone library is accessible at runtime, not just the headers. The flag `-Xlog:os+dll` can reveal library loading details.

### "Build fails with capstone.h not found"

The include path needs to point to the directory *containing* `capstone.h`. On Apple Silicon:
```bash
# Headers are here (note the capstone subdirectory):
ls /opt/homebrew/opt/capstone/include/capstone/capstone.h
```

### "Undefined symbols: _cs_open"

The Capstone library isn't being linked. Make sure `-L` points to the directory containing `libcapstone.dylib` and that `-lcapstone` is present in the command.

## Alternatives to the OpenJDK Build System?

Direct compilation is the alternative, and it works because the OpenJDK build system (`configure && make build-hsdis`) is designed to build the *entire JDK*, not just the `hsdis` plugin. On macOS, this means requiring a full Xcode installation (not just Command Line Tools), the Metal shader compiler (`metal`, `metallib`), and autoconf among other tools.

For a ~50KB shared library with one source file, this is unnecessary complexity. Direct compilation against Capstone produces an equivalent binary that satisfies the JVM's contract, works with just Command Line Tools, avoids Metal and other macOS-specific build requirements, and demonstrates how little the JVM actually requires.

## What Does JIT Observability Look Like?

Once the disassembly plugin is in place, the JVM's machine code output becomes actionable. JMH's `perfasm` profiler[^perfasm] can now correlate CPU samples with the actual instructions executed:

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

Now we're getting somewhere. The percentages on the left show where cycles are spent. This loop is spending ~35% on the load, ~29% on the add, and ~31% on the loop comparison. The bounds check (`b.hs`) is outside the hot path, meaning the JIT hoisted it.

This is the observability that `hsdis` enables: seeing not just *that* the JIT optimized your code, but *how*. Combined with [async-profiler](https://github.com/async-profiler/async-profiler)'s flamegraphs[^flamegraph], you have the tools to understand what the JVM is actually doing with your code.

> Flamegraphs tell you *where* time is spent. `PrintAssembly` tells you *why*. Together with `hsdis`, they close the gap between "this method is hot" and "these specific instructions are the bottleneck."
{: .prompt-tip }

## Conclusion

The JVM's `PrintAssembly` capability exposes the JIT's actual output, but requires a disassembly plugin to be useful. Understanding what the JVM actually expects from `hsdis` reveals that it can be compiled directly against Capstone, bypassing the complexity of the full OpenJDK build.

The result is JIT observability: the ability to see the actual machine code the JIT produced, not just profiler hotspots. When the flamegraph points to a hot method and you need to know *why*, `hsdis` is what turns `<unknown>` into answers.

## Appendix: Quick Reference

For convenience, here is the complete sequence as a single command:

```bash
# One-liner for Apple Silicon (M1/M2/M3/M4)
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

- [OpenJDK `hsdis` source](https://github.com/openjdk/jdk/tree/master/src/utils/hsdis): The official source files
- [Capstone Engine](https://www.capstone-engine.org/): Multi-architecture disassembly framework
- [HotSpot PrintAssembly Wiki](https://wiki.openjdk.org/display/HotSpot/PrintAssembly): Official documentation
- [JMH Profilers](https://github.com/openjdk/jmh/blob/master/jmh-core/src/main/java/org/openjdk/jmh/profile/): Using `hsdis` with JMH benchmarks
- [JITWatch](https://github.com/AdoptOpenJDK/jitwatch): Log analyzer and visualizer for HotSpot JIT compilation
- [Nitsan Wakart's Blog](https://psy-lob-saw.blogspot.com/): Deep dives into JVM performance and assembly analysis

[^metal]: [Metal](https://developer.apple.com/metal/) is Apple's GPU programming framework. The OpenJDK build system requires its shader compiler tools (`metal`, `metallib`) because the JDK includes macOS-specific rendering components that use GPU acceleration. These tools are part of the full Xcode installation and have no connection to `hsdis` or disassembly.
[^shallow-clone]: A [shallow clone](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---depthltdepthgt) (`--depth 1`) fetches only the latest commit on the specified branch, without the full history. For large repositories like OpenJDK, this reduces the download from over 1GB to about 200MB. The trade-off is that you cannot browse history or switch branches, but for grabbing source files this is all you need.
[^inline-cache]: An [inline cache](https://wiki.openjdk.org/display/HotSpot/Glossary) is a JIT optimization for virtual method dispatch. Instead of performing a full vtable lookup on every call, the JIT caches the target method at the call site. When the receiver type changes (a "miss"), execution falls through to the `ic_miss_stub`, which updates the cache or deoptimizes.
[^perfasm]: The `perfasm` profiler in [JMH](https://github.com/openjdk/jmh) samples hardware performance counters and maps the results to disassembled instructions. It requires `hsdis` to be installed so it can translate machine code addresses into readable assembly. On Linux it uses `perf`, on macOS it falls back to `PrintAssembly` output.
[^flamegraph]: [Flamegraphs](https://www.brendangregg.com/flamegraphs.html), originally developed by Brendan Gregg, are a visualization of profiled stack traces where the x-axis represents the proportion of samples and the y-axis shows the call stack depth. They make it easy to spot which methods consume the most CPU time, but they do not reveal what happens *inside* those methods at the instruction level.
[^dyld]: `DYLD_LIBRARY_PATH` is the macOS equivalent of `LD_LIBRARY_PATH` on Linux. It tells the dynamic linker where to search for shared libraries (`.dylib` files) at runtime. Note that on macOS, [System Integrity Protection](https://support.apple.com/en-us/102149) strips this variable for system-protected executables, but it works fine for user-installed JVMs.
