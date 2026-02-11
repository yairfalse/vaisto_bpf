defmodule VaistoBpf do
  @moduledoc """
  Compiles a restricted subset of Vaisto typed AST to eBPF bytecode.

  This is to Vaisto what Aya is to Rust — an independent eBPF backend
  that consumes the typed AST produced by `Vaisto.TypeChecker`.

  ## Pipeline

      typed_ast → validate → emit IR → assemble → binary instructions

  ## Usage

      # From source (recommended):
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      {:ok, instructions} = VaistoBpf.compile_source(source)

      # From pre-typed AST (Phase 1 API):
      {:ok, instructions} = VaistoBpf.compile(typed_ast)
  """

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker
  alias VaistoBpf.Validator
  alias VaistoBpf.Emitter
  alias VaistoBpf.Assembler

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
  Validate that a typed AST is within the BPF-compilable subset.

  Useful for checking before compilation, e.g. in an IDE.
  """
  @spec validate(term()) :: {:ok, term()} | {:error, Vaisto.Error.t()}
  def validate(typed_ast) do
    Validator.validate(typed_ast)
  end
end
