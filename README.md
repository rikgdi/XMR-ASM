# XMRASM

RandomX (V1) Monero CPU miner for Windows x86-64, written entirely in MASM
assembly (`src/*.asm`). No C/C++ sources, no external libraries — the full
RandomX pipeline (superscalar program generation, cache, dataset, JIT, VM,
stratum client) is implemented from scratch in `.asm` files.

---

## Requirements

- **OS:** Windows 10/11 x64
- **Toolchain:** Visual Studio with MSVC + MASM (ml64) — `build.bat` auto-detects
  via `vswhere`, or set `VCVARS64` to your `vcvars64.bat`
- **RAM:** ~2.4 GB free (enforced 4 GB hard cap at startup)
- **Network:** Internet access to a Monero stratum pool

---

## Build

```bat
build.bat          rem assemble src\*.asm -> obj\, link -> xmrasm.exe
build.bat clean    rem remove obj\ and the exe
```

The build script:
1. Locates `vcvars64.bat` via `vswhere` (or `VCVARS64` env var)
2. Assembles all `src\*.asm` to `obj\*.obj` with `ml64`
3. Links statically against the UCRT (`libcmt.lib`, `libvcruntime.lib`, `libucrt.lib`)
   plus `kernel32.lib`, `user32.lib`, `ws2_32.lib`, `advapi32.lib`
4. Outputs `xmrasm.exe` in the repo root

---

## Configuration

**Wallet address and pool are compile-time constants.** You **must** edit the
following files before building and replace the placeholder values with your own:

| File | Constant | Default |
|------|----------|---------|
| `src/stratum.asm` | `st_wallet` | `YOUR_XMR_WALLET_ADDRESS_HERE` **(replace with your address)** |
| `src/miner.asm` | `st_host` | `pool.supportxmr.com` |
| `src/miner.asm` | `st_port` | `3333` |

> **Important:** The default `st_wallet` is set to `YOUR_XMR_WALLET_ADDRESS_HERE`
> — a literal placeholder string. You **must change it to your own Monero address**
> (95-char base58, starting with `4` or `8`) before mining, otherwise any
> hashrate you contribute will be lost.
>
> Optionally change `st_host`/`st_port` to your preferred pool.

After editing, run `build.bat` again to produce a customized `xmrasm.exe`.

---

## Run

```bat
xmrasm.exe
```

**Startup sequence:**

1. **Self-tests** — 40 tests (8 official RandomX KAT vectors, JIT-vs-interpreter
   equivalence, VM flow). Must pass (0 failures) or the miner exits.
2. **Memory budget** — prints e.g. `memory budget: 2344 MB (cap 4096 MB)`.
3. **Stratum connect** — logs in to configured pool, receives first job.
4. **Dataset build** — `dataset: initializing NN%` (~2–3 min; workers parked,
   hashrate reads 0 H/s).
5. **Mining** — `hashrate N H/s | found N accepted N rejected N dropped N`
   every 5 seconds.

Stop with `Ctrl+C`.

---

## Design Overview

| Component | Source File(s) |
|-----------|----------------|
| Entry / self-tests | `main.asm`, `tests.asm` |
| RandomX cache + superscalar | `cache.asm`, `superscalar.asm`, `argon2.asm`, `blake2b.asm` |
| Dataset (2 GiB + extra) | `dataset.asm` |
| JIT (code gen + 30 handlers) | `jit_emit.asm`, `jit_frag.asm` |
| VM interpreter (light mode) | `vm.asm` |
| AES / hashing primitives | `aes.asm`, `blake2gen.asm` |
| Stratum protocol + jobs | `stratum.asm`, `json.asm` |
| Networking (Winsock) | `net.asm` |
| Orchestration (threads, shares, stats) | `miner.asm` |
| Console / alloc / CPU info | `console.asm`, `mem.asm`, `cpu.asm` |

**Key implementation details:**

- **RandomX version:** V1 only (never `RANDOMX_FLAG_V2`).
- **Execution strategy:** JIT — dataset items compiled to native code and
  executed directly; full-mode scratchpad is 2 MiB per VM.
- **Memory budget (4 GB cap, checked before any allocation):**
  dataset 2181038016 B + cache 268501840 B + per-thread VM/machine —
  refuses to start if the total would exceed 4 GiB.
- **Share validation:** target folded big-endian from stratum `target` field;
  `LE64(hash+24) <= target`, difficulty printed per job (pool typically uses 75000).

---

## Verification

- 40/40 self-tests pass on every launch (includes 8 official RandomX KAT
  vectors, 16/16 JIT-vs-interpreter driver equivalence, VM flow test).
- Live-verified: shares accepted by `pool.supportxmr.com`, correct difficulty,
  stable RAM usage under the 4 GB cap.

---

## Contributing

This is an open source project — contributions are welcome! Feel free to:

- Open issues for bugs, feature requests, or questions
- Submit pull requests with improvements, optimizations, or fixes
- Improve documentation, tests, or build scripts
- Port to other platforms (Linux, macOS) or assemblers (NASM, FASM)

Please keep changes focused and include relevant test updates where applicable.

---

## Donations

If you find this project useful and want to support development:

**XMR (Monero):**
```
4A69nC3FCw8RugfQ2ybBXjfqqd174v14jFydMpXKFDY2hZbKYW5aGfEUycZCJL3FELeumDXxUK4NxTuBU5e7VmJKGAbBua7
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.