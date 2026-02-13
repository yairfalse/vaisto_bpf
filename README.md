# vaisto_bpf

An eBPF backend for the [Vaisto](https://github.com/yairfalse/vaisto) programming language. Compiles a restricted subset of Vaisto's typed AST to eBPF bytecode — the same relationship as [Aya](https://aya-rs.dev/) to Rust.

Write eBPF programs in a statically-typed S-expression syntax, get type-safe kernel interaction without touching C.

## Example

```scheme
; Declare kernel helpers
(extern bpf:ktime_get_ns [] :u64)
(extern bpf:map_lookup_elem [:u64 :u64] :u64)

; Pure arithmetic — compiles to ALU64 instructions
(defn add [x :u64 y :u64] :u64 (+ x y))

; Call kernel helpers — args go to r1-r5, return in r0
(defn get_time [] :u64 (bpf/ktime_get_ns))

; Variables survive across helper calls via register spilling
(defn elapsed_since [start :u64] :u64
  (let [now (bpf/ktime_get_ns)]
    (- now start)))

; Multi-arg helpers
(defn lookup [map_fd :u64 key :u64] :u64
  (bpf/map_lookup_elem map_fd key))
```

## Usage

```elixir
source = """
(extern bpf:ktime_get_ns [] :u64)
(defn get_time [] :u64 (bpf/ktime_get_ns))
"""

# Full pipeline: preprocess → parse → normalize → type check → validate → emit → assemble
{:ok, bytecode} = VaistoBpf.compile_source(source)

# bytecode is a list of 8-byte BPF instruction binaries
length(bytecode)  #=> 4

# Or compile directly to an ELF object file (.o)
{:ok, elf} = VaistoBpf.compile_source_to_elf(source)
File.write!("prog.o", elf)
# Load with: bpftool prog load prog.o /sys/fs/bpf/my_prog
```

## Pipeline

```
.va source
  |> Preprocessor.preprocess_source/1    # :u64 → :U64 (capitalize trick)
  |> Vaisto.Parser.parse/1               # S-expressions → AST
  |> Preprocessor.normalize_ast/1        # :U64 → :u64 (reverse in AST)
  |> BpfTypeChecker.check/1              # Verify type annotations
  |> Validator.validate/1                # Reject unsupported constructs
  |> Emitter.emit/1                      # Typed AST → BPF IR
  |> Assembler.assemble/1                # IR → 8-byte instructions
  |> ElfWriter.to_elf/2                  # Instructions → ELF object file
```

## Modules

| Module | Purpose |
|--------|---------|
| `VaistoBpf` | Public API: `compile_source/1`, `compile_source_to_elf/2`, `compile/1`, `compile_to_elf/2`, `validate/1` |
| `VaistoBpf.Preprocessor` | Bridges vaisto parser and BPF types via the capitalize trick |
| `VaistoBpf.BpfTypeChecker` | Verification-based type checker (not HM inference) |
| `VaistoBpf.Validator` | Rejects floats, strings, closures, recursion, processes |
| `VaistoBpf.Emitter` | Typed AST → linear BPF IR with register allocation |
| `VaistoBpf.Assembler` | Two-pass assembly: label resolution + binary encoding |
| `VaistoBpf.Helpers` | BPF helper registry: kernel function IDs and type signatures |
| `VaistoBpf.ElfWriter` | Wraps BPF bytecode in ELF relocatable object files (.o) |
| `VaistoBpf.Types` | Opcodes, registers, instruction encoding/decoding |
| `VaistoBpf.Layout` | C struct layout calculator (alignment, padding) |
| `VaistoBpf.DecoderGenerator` | Auto-generates BEAM-side binary decoders for BPF record types |
| `VaistoBpf.IR` | IR type definitions |

## What BPF Supports

- Fixed-width integers: `:u8`, `:u16`, `:u32`, `:u64`, `:i8`, `:i16`, `:i32`, `:i64`
- Arithmetic: `+`, `-`, `*`, `div`, `rem`
- Bitwise: `band`, `bor`, `bxor`, `bsl`, `bsr`
- Comparisons: `==`, `!=`, `>`, `<`, `>=`, `<=`
- Control flow: `if`/`else`, `match`, `let` bindings
- Named functions with explicit type annotations
- Kernel helper calls via `(extern bpf:name [...] :ret)` + `(bpf/name args...)`
- Record types with C-compatible layout

## What BPF Rejects (with helpful errors)

- Floats, strings, dynamic lists, maps, tuples
- Anonymous functions and closures
- Recursion (kernel verifier rejects it)
- Processes, receive, supervision
- Standard `:int`/`:float`/`:any` types (must use fixed-width)

## BPF Helper Calls

Declare helpers with `extern` (colon syntax), call with qualified names (slash syntax):

```scheme
(extern bpf:ktime_get_ns [] :u64)        ; declaration
(bpf/ktime_get_ns)                        ; call
```

Available helpers:

| Helper | ID | Args | Return |
|--------|----|------|--------|
| `ktime_get_ns` | 5 | `[]` | `:u64` |
| `get_smp_processor_id` | 8 | `[]` | `:u32` |
| `get_current_pid_tgid` | 14 | `[]` | `:u64` |
| `get_current_uid_gid` | 15 | `[]` | `:u64` |
| `map_lookup_elem` | 1 | `[:u64 :u64]` | `:u64` |
| `map_update_elem` | 2 | `[:u64 :u64 :u64 :u64]` | `:u64` |
| `map_delete_elem` | 3 | `[:u64 :u64]` | `:u64` |
| `probe_read` | 4 | `[:u64 :u64 :u64]` | `:u64` |
| `trace_printk` | 6 | `[:u64 :u64]` | `:u64` |

The emitter handles the BPF calling convention automatically: args are placed in r1-r5, live variables are spilled to callee-saved registers r6-r9 before the call, and the result is captured from r0.

## Register Model

```
r0       return value / helper call result
r1-r5    function arguments / caller-saved (clobbered by helper calls)
r6-r9    callee-saved (spill targets for live variables)
r10      read-only frame pointer
```

## Development

```bash
# Dependencies (requires sibling vaisto checkout)
mix deps.get

# Run tests (175 tests)
mix test

# Run a specific test file
mix test test/helper_call_test.exs
```

## Requirements

- Elixir ~> 1.17
- [vaisto](https://github.com/yairfalse/vaisto) (sibling directory)

## Status

Phase 4 complete. The compiler handles arithmetic, control flow, function definitions, record types, kernel helper calls, and ELF output. Next up: BPF map definitions and source maps.
