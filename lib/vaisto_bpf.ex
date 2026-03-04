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

      # With BPF maps:
      source = \"""
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64 (bpf/map_lookup_elem counters key))
      \"""
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      # From pre-typed AST (Phase 1 API):
      {:ok, instructions} = VaistoBpf.compile(typed_ast)
  """

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker
  alias VaistoBpf.Safety
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
         {:ok, instructions, _relocations, _func_offsets, _core_relos} <- Assembler.assemble(ir) do
      {:ok, instructions}
    end
  end

  @doc """
  Compile a Vaisto source string with BPF types directly to eBPF bytecode.

  Handles the full pipeline: extract defmaps → preprocess → parse → normalize
  → BPF type check → validate → emit → assemble.

  Supports `(defmap name :type :key :val max_entries)` declarations.

  Returns `{:ok, bytecode}` or `{:error, %Vaisto.Error{}}`.
  """
  @spec compile_source(String.t()) :: {:ok, [binary()]} | {:error, Vaisto.Error.t()}
  def compile_source(source) do
    {cleaned, _section, prog_type} = Preprocessor.extract_program(source)
    {cleaned, maps} = Preprocessor.extract_defmaps(cleaned)
    {cleaned, globals} = Preprocessor.extract_defglobals(cleaned)
    preprocessed = Preprocessor.preprocess_source(cleaned)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)

    with {:ok, _type, typed_ast} <- BpfTypeChecker.check(normalized, maps, prog_type, globals),
         :ok <- Safety.check(typed_ast),
         {:ok, ast} <- Validator.validate(typed_ast),
         {:ok, ir} <- Emitter.emit(ast, maps, globals),
         {:ok, instructions, _relocations, _func_offsets, _core_relos} <- Assembler.assemble(ir) do
      {:ok, instructions}
    end
  end

  @doc """
  Compile a Vaisto source string to an ELF relocatable object binary.

  Runs the full pipeline and wraps the output in ELF format suitable
  for `bpftool prog load` or libbpf. When `defmap` declarations are present,
  the ELF includes `.maps`, `.BTF`, and `.rel.text` sections.

  Options: `:section`, `:license`, `:function_name` (see `VaistoBpf.ElfWriter`).
  """
  @spec compile_source_to_elf(String.t(), keyword()) :: {:ok, binary()} | {:error, Vaisto.Error.t()}
  def compile_source_to_elf(source, opts \\ []) do
    {cleaned, section_name, prog_type} = Preprocessor.extract_program(source)
    {cleaned, maps} = Preprocessor.extract_defmaps(cleaned)
    {cleaned, globals} = Preprocessor.extract_defglobals(cleaned)
    preprocessed = Preprocessor.preprocess_source(cleaned)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)

    with {:ok, _type, typed_ast} <- BpfTypeChecker.check(normalized, maps, prog_type, globals),
         :ok <- Safety.check(typed_ast),
         {:ok, ast} <- Validator.validate(typed_ast),
         {:ok, ir} <- Emitter.emit(ast, maps, globals, opts),
         {:ok, instructions, relocations, func_offsets, core_relos} <- Assembler.assemble(ir) do
      func_sigs = extract_function_signatures(typed_ast)
      elf_opts = opts ++ [maps: maps, relocations: relocations, func_offsets: func_offsets,
                          globals: globals, func_sigs: func_sigs, core_relos: core_relos]
      elf_opts = if section_name, do: Keyword.put_new(elf_opts, :section, section_name), else: elf_opts
      elf_opts = if prog_type, do: Keyword.put_new(elf_opts, :prog_type, prog_type), else: elf_opts
      ElfWriter.to_elf(instructions, elf_opts)
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
  Compile source and extract the program type for loading.

  Returns `{:ok, elf_binary, prog_type}` where `prog_type` is an atom
  like `:xdp`, `:kprobe`, `:tracepoint`, etc. (or `nil` for auto-detect).
  """
  @spec compile_source_with_type(String.t(), keyword()) ::
          {:ok, binary(), atom() | nil} | {:error, Vaisto.Error.t()}
  def compile_source_with_type(source, opts \\ []) do
    {_cleaned, _section_name, prog_type} = Preprocessor.extract_program(source)

    case compile_source_to_elf(source, opts) do
      {:ok, elf} -> {:ok, elf, prog_type}
      error -> error
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

  # Extract function signatures from the typed AST for BTF generation.
  # Returns a list of {name, param_types, ret_type} tuples.
  defp extract_function_signatures({:module, forms}) do
    forms
    |> Enum.filter(&match?({:defn, _, _, _, _}, &1))
    |> Enum.map(fn {:defn, name, params, _body, fn_type} ->
      param_types = extract_param_types(params, fn_type)
      ret_type = extract_ret_type(fn_type)
      {name, param_types, ret_type}
    end)
  end

  defp extract_function_signatures(_), do: []

  defp extract_param_types(_params, {:fn, param_types, _ret}) do
    Enum.map(param_types, &normalize_btf_type/1)
  end

  defp extract_param_types(_params, _fn_type), do: []

  defp extract_ret_type({:fn, _params, ret}), do: normalize_btf_type(ret)
  defp extract_ret_type(_), do: :u64

  defp normalize_btf_type(type) when type in [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64], do: type
  defp normalize_btf_type(:bool), do: :bool
  defp normalize_btf_type(:unit), do: :unit
  defp normalize_btf_type(_), do: :u64
end
