defmodule VaistoBpf do
  @moduledoc """
  Compiles a restricted subset of Vaisto typed AST to eBPF bytecode.

  This is to Vaisto what Aya is to Rust — an independent eBPF backend
  that consumes the typed AST produced by `Vaisto.TypeChecker`.

  ## Pipeline

      typed_ast → validate → emit IR → assemble → binary instructions → ELF (.o)

  ## Usage

      # From source to bytecode:
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      {:ok, instructions} = VaistoBpf.compile_source(source)

      # From source to ELF object file:
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      File.write!("prog.o", elf)

      # From pre-typed AST (Phase 1 API):
      {:ok, instructions} = VaistoBpf.compile(typed_ast)
  """

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker
  alias VaistoBpf.Validator
  alias VaistoBpf.Emitter
  alias VaistoBpf.Assembler
  alias VaistoBpf.ElfWriter

  @doc """
  Compile typed Vaisto AST to eBPF bytecode.

  Returns `{:ok, bytecode}` where bytecode is a list of 8-byte instruction binaries,
  or `{:error, %Vaisto.Error{}}` on failure.
  """
  @spec compile(term()) :: {:ok, [binary()]} | {:error, Vaisto.Error.t()}
  def compile(typed_ast) do
    with {:ok, ast} <- Validator.validate(typed_ast),
         {:ok, ir} <- Emitter.emit(ast),
         {:ok, instructions} <- Assembler.assemble(ir) do
      {:ok, instructions}
    end
  end

  @doc """
  Compile a Vaisto source string with BPF types directly to eBPF bytecode.

  Handles the full pipeline: preprocess (`:u64` → `:U64`) → parse → normalize
  (`:U64` → `:u64`) → BPF type check → validate → emit → assemble.

  ## Example

      source = \"""
      (defn add [x :u64 y :u64] :u64 (+ x y))
      \"""
      {:ok, instructions} = VaistoBpf.compile_source(source)

  Returns `{:ok, bytecode}` or `{:error, %Vaisto.Error{}}`.
  """
  @spec compile_source(String.t()) :: {:ok, [binary()]} | {:error, Vaisto.Error.t()}
  def compile_source(source) do
    preprocessed = Preprocessor.preprocess_source(source)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)

    with {:ok, _type, typed_ast} <- BpfTypeChecker.check(normalized) do
      compile(typed_ast)
    end
  end

  @doc """
  Compile a Vaisto source string to an ELF relocatable object binary.

  Runs the full pipeline and wraps the output in ELF format suitable
  for `bpftool prog load` or libbpf.

  Options: `:section`, `:license`, `:function_name` (see `VaistoBpf.ElfWriter`).
  """
  @spec compile_source_to_elf(String.t(), keyword()) :: {:ok, binary()} | {:error, Vaisto.Error.t()}
  def compile_source_to_elf(source, opts \\ []) do
    with {:ok, instructions} <- compile_source(source) do
      ElfWriter.to_elf(instructions, opts)
    end
  end

  @doc """
  Compile typed Vaisto AST to an ELF relocatable object binary.

  Options: `:section`, `:license`, `:function_name` (see `VaistoBpf.ElfWriter`).
  """
  @spec compile_to_elf(term(), keyword()) :: {:ok, binary()} | {:error, Vaisto.Error.t()}
  def compile_to_elf(typed_ast, opts \\ []) do
    with {:ok, instructions} <- compile(typed_ast) do
      ElfWriter.to_elf(instructions, opts)
    end
  end

  @doc """
  Validate that a typed AST is within the BPF-compilable subset.

  Useful for checking before compilation, e.g. in an IDE.
  """
  @spec validate(term()) :: {:ok, term()} | {:error, Vaisto.Error.t()}
  def validate(typed_ast) do
    Validator.validate(typed_ast)
  end
end
