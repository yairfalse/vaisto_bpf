defmodule VaistoBpf do
  @moduledoc """
  Compiles a restricted subset of Vaisto typed AST to eBPF bytecode.

  This is to Vaisto what Aya is to Rust — an independent eBPF backend
  that consumes the typed AST produced by `Vaisto.TypeChecker`.

  ## Pipeline

      typed_ast → validate → emit IR → assemble → binary instructions

  ## Usage

      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      {:ok, ast} = Vaisto.Parser.parse(source)
      {:ok, _type, typed_ast} = Vaisto.TypeChecker.check(ast)
      {:ok, instructions} = VaistoBpf.compile(typed_ast)
  """

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
  Validate that a typed AST is within the BPF-compilable subset.

  Useful for checking before compilation, e.g. in an IDE.
  """
  @spec validate(term()) :: {:ok, term()} | {:error, Vaisto.Error.t()}
  def validate(typed_ast) do
    Validator.validate(typed_ast)
  end
end
