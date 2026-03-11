# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

eBPF backend for the Vaisto programming language. Compiles S-expression source through a multi-stage pipeline into ELF object files loadable by libbpf/bpftool. Think Aya-to-Rust, but for Vaisto.

## Commands

```bash
mix deps.get                              # Requires ../vaisto sibling checkout
mix compile                               # On Linux: also builds c_src/bpf_loader.c → priv/bpf_loader
mix test                                  # ~722 tests; :linux tag excluded by default
mix test test/codec_test.exs              # Single file
mix test test/codec_test.exs:42           # Single test by line
mix test --include linux                  # Include kernel integration tests (Linux only)
```

Linux C build requires: `libbpf-dev`, `libelf-dev`, `zlib1g-dev`. For Linux testing from macOS:

```bash
docker compose run test                   # Runs mix test --include linux
docker compose run shell                  # Interactive shell for development
```

## Compilation Pipeline

```
Source string
  → Preprocessor.extract_program/1          # strip (program :xdp) annotation
  → Preprocessor.extract_defmaps/1          # strip (defmap ...) → [%MapDef{}]
  → Preprocessor.extract_defglobals/1       # strip (defglobal/defconst ...) → [%GlobalDef{}]
  → Preprocessor.preprocess_source/1        # text: :u64 → :U64 (capitalize trick)
  → Vaisto.Parser.parse/1                   # S-expressions → raw AST (from sibling vaisto dep)
  → Preprocessor.normalize_ast/1            # AST: :U64 → :u64 (reverse trick)
  → BpfTypeChecker.check/4                  # verification-based type checking
  → Safety.check/1                          # div-by-zero, shift bounds, call depth (max 8)
  → Validator.validate/1                    # reject floats, closures, recursion, processes
  → Emitter.emit/4                          # typed AST → IR with register allocation
  → Assembler.assemble/1                    # two-pass: labels → 8-byte BPF instructions
  → ElfWriter.to_elf/2                      # instructions → ELF .o with BTF, .maps, relocations
```

Three public entry points in `VaistoBpf`: `compile_source/1` (bytecode), `compile_source_to_elf/2` (ELF binary), `compile_source_to_schema/2` (ELF + metadata with codecs).

## Two-Pass Assembly & ELF

The Assembler runs two passes: (1) builds `%{label => instruction_index}` accounting for wide instructions (ld_map_fd = 2 slots), (2) emits 8-byte binaries with resolved jump offsets and collects map/global/CO-RE relocations. ELF output is minimal ELF-64 relocatable (ET_REL, EM_BPF=247). Without maps: 6 sections. With maps/globals/BTF: 9+ sections including `.BTF`, `.BTF.ext`, `.rel.text`, `.bss`/`.data`/`.rodata`.

## C Port Protocol

The Loader communicates with `priv/bpf_loader` via Erlang port with `{:packet, 2}`. Commands: LOAD_XDP(0x01), DETACH(0x02), MAP_LOOKUP(0x03), MAP_UPDATE(0x04), MAP_DELETE(0x05), SUBSCRIBE_RINGBUF(0x06), UNSUBSCRIBE_RINGBUF(0x07), MAP_GET_NEXT_KEY(0x08), LOAD(0x09), SUBSCRIBE_PERFBUF(0x0A), UNSUBSCRIBE_PERFBUF(0x0B). Unsolicited events: ring buffer data(0x10), perf buffer data(0x11), perf buffer lost(0x12). Protocol encode/decode lives in `loader/protocol.ex`. The C port handles up to 16 loaded BPF objects, 8 ring buffer and 8 perf buffer subscriptions via epoll.

## Runtime Layer (Phases 7-10)

- **Schema** (`schema.ex`) — captures compile-time metadata (map schemas with codecs, globals, records, function sigs) so it survives the ELF boundary
- **Codec** (`codec.ex`) — runtime `{encode_fn, decode_fn}` closure pairs for BPF primitives and C-aligned records; supports nested records via `for_type/2` with `record_defs`
- **Program** (`program.ex`) — GenServer wrapping a loaded BPF program; typed map access (`map_lookup/3` auto-encodes key, auto-decodes value), ring buffer and perf buffer event dispatch with subscriber monitoring, global read/write by name
- **Loader** (`loader.ex`) — GenServer managing the C port; request queuing via `:queue`, drains queue on port exit
- **Application** (`application.ex`) — starts Loader + DynamicSupervisor on Linux only; empty on macOS
- **Telemetry** (`telemetry.ex`) — `:telemetry` events for compile spans, map ops, program lifecycle, ringbuf/perfbuf events, verifier rejections

## Key Design Patterns

**Capitalize trick**: Vaisto's parser only recognizes capitalized atoms as types. BPF uses lowercase (`:u64`). Preprocessor does text-level `:u64→:U64` before parsing, then reverses in AST. Transparent to the rest of the compiler.

**Register allocation**: Linear free-list over r1–r9. Before helper calls, live caller-saved registers (r1–r5) are spilled to callee-saved (r6–r9). Stack limit: 512 bytes, with 32 bytes per function for r6–r9 save area.

**Nullable pointers**: `map_lookup_elem` returns `{:ptr, T}`. Pattern match with `(Some ptr)/(None)` — exhaustiveness-checked at compile time.

**Platform split**: Compilation works everywhere. Loading/running BPF programs requires Linux. `Application` detects via `:os.type()`. The C port binary is only built on Linux. `VaistoBpf.run/3` checks `runtime_available?()` and returns `{:error, :runtime_not_available}` on non-Linux.

**Codec nil safety**: Map operations in Program check codecs via `require_codecs/1` and `require_key_codec/1`, returning `{:error, {:missing_codec, name}}` instead of crashing on nil codecs (ringbuf maps, unresolved types).

## Source Language Syntax

```scheme
(program :xdp)                              ; program type declaration
(defmap counters :hash :u32 :u64 1024)      ; map definition
(defmap events :perf_event_array 0 0 128)   ; perf event buffer (per-CPU)
(defglobal counter :u64)                    ; mutable global (.bss)
(defconst max_val :u32 100)                 ; read-only global (.rodata)
(deftype Event [ts :u64 pid :u32])          ; record type (NOT (product [...]))
(extern bpf:map_lookup_elem [:u64 :u64] :u64)  ; kernel helper declaration
(defn name [param :type ...] :ret_type body)    ; function

(let [x (+ a b)] x)                        ; let binding (NO type annotation)
(match (bpf/map_lookup_elem m k)            ; nullable pointer pattern match
  [(Some ptr) (bpf/load_u64 ptr 0)]
  [(None) 0])
(. ctx :field_name)                         ; field access on context structs
(do expr1 expr2)                            ; sequential side effects
```

Context types: `XdpMd`, `SkBuff`, `PtRegs`, `BpfSock`, `BpfSockAddr`, `BpfSkMsg`, `BpfFlowKeys` — auto-injected based on program type.

## Test Structure

- `ExUnit.start(exclude: [:linux])` — kernel tests excluded by default
- Only `loader_integration_test.exs` requires Linux (`@moduletag :linux`)
- Most test files use `async: true`
- No mock libraries; `test/program_test.exs` uses an inline `MockLoader` GenServer
- Example programs in `examples/` are compile-tested in `examples_test.exs`
- `test/program_test.exs` inline `MockLoader` pattern: a GenServer that mimics the Loader API with in-memory maps — use this pattern when testing Program interactions without Linux
- MockLoader tracks calls (detach_calls, unsubscribe_calls) for assertion in tests
