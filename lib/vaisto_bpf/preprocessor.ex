defmodule VaistoBpf.Preprocessor do
  @moduledoc """
  Bridges vaisto's parser and BPF fixed-width types using the "capitalize trick".

  vaisto's parser recognizes capitalized atoms as user-defined types (`:U64`)
  but not lowercase BPF types (`:u64`). This module:

  1. `preprocess_source/1` — text-level: `:u64` → `:U64` before parsing
  2. `normalize_ast/1` — AST-level: `:U64` → `:u64` after parsing

  3. `extract_defmaps/1` — text-level: extract `(defmap ...)` forms before parsing

  This keeps all BPF intelligence in vaisto_bpf with zero changes to vaisto core.
  """

  alias VaistoBpf.MapDef

  # Maps lowercase BPF type atoms to their capitalized parser-friendly form,
  # and vice versa.
  @bpf_types ~w(u8 u16 u32 u64 i8 i16 i32 i64)a
  @capitalize_map Map.new(@bpf_types, fn t ->
    {t, t |> Atom.to_string() |> String.upcase() |> String.to_atom()}
  end)
  @normalize_map Map.new(@capitalize_map, fn {lower, upper} -> {upper, lower} end)

  # Regex that matches :u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64
  # as whole-word type annotations (preceded by whitespace or bracket)
  @type_pattern ~r/:(u8|u16|u32|u64|i8|i16|i32|i64)\b/

  @doc """
  Replace lowercase BPF type annotations in source text with capitalized versions.

  `:u64` becomes `:U64`, `:i32` becomes `:I32`, etc. This lets vaisto's parser
  recognize them as user-defined type annotations.
  """
  @spec preprocess_source(String.t()) :: String.t()
  def preprocess_source(source) do
    Regex.replace(@type_pattern, source, fn _full_match, type_name ->
      ":" <> String.upcase(type_name)
    end)
  end

  # Regex matching (program :type) or (program :type "attach_point")
  @program_pattern ~r/\(program\s+:(\w+)(?:\s+"([^"]*)")?\)/

  @supported_program_types ~w(kprobe kretprobe uprobe uretprobe xdp tc
    tracepoint raw_tracepoint socket_filter cgroup_skb)

  @doc """
  Extract `(program ...)` annotation from source text.

  Returns `{cleaned_source, section_name | nil}` where section_name is
  the ELF section name derived from the program type and optional attach point.
  """
  @spec extract_program(String.t()) :: {String.t(), String.t() | nil}
  def extract_program(source) do
    case Regex.run(@program_pattern, source) do
      [full, prog_type, attach_point] ->
        if prog_type in @supported_program_types do
          replacement = String.duplicate(" ", String.length(full))
          cleaned = String.replace(source, full, replacement, global: false)
          {cleaned, build_section_name(prog_type, attach_point)}
        else
          raise "unsupported program type: #{prog_type}"
        end

      [full, prog_type] ->
        if prog_type in @supported_program_types do
          replacement = String.duplicate(" ", String.length(full))
          cleaned = String.replace(source, full, replacement, global: false)
          {cleaned, build_section_name(prog_type, nil)}
        else
          raise "unsupported program type: #{prog_type}"
        end

      nil ->
        {source, nil}
    end
  end

  defp build_section_name(prog_type, nil), do: prog_type
  defp build_section_name(prog_type, ""), do: prog_type
  defp build_section_name(prog_type, attach_point), do: "#{prog_type}/#{attach_point}"

  # Regex matching (defmap name :type :key/:val max_entries)
  # Supports both :atom types and bare 0 (for ringbuf)
  @defmap_pattern ~r/\(defmap\s+(\w+)\s+:(\w+)\s+:?(\w+)\s+:?(\w+)\s+(\d+)\)/

  @doc """
  Extract `(defmap ...)` forms from source text before parsing.

  Returns `{cleaned_source, [%MapDef{}]}` where the cleaned source has defmap
  forms replaced with whitespace (preserving line numbers), and the list
  contains validated MapDef structs with 0-based indices.
  """
  @spec extract_defmaps(String.t()) :: {String.t(), [MapDef.t()]}
  def extract_defmaps(source) do
    matches = Regex.scan(@defmap_pattern, source)

    if matches == [] do
      {source, []}
    else
      {cleaned, map_defs, _index} =
        Enum.reduce(matches, {source, [], 0}, fn
          [full, name, map_type, key_type, val_type, max_entries], {src, maps, idx} ->
            # Replace the matched form with spaces (preserve line structure)
            replacement = String.duplicate(" ", String.length(full))
            src = String.replace(src, full, replacement, global: false)

            {:ok, md} = MapDef.new(
              String.to_atom(name),
              String.to_atom(map_type),
              parse_defmap_type(key_type),
              parse_defmap_type(val_type),
              String.to_integer(max_entries),
              idx
            )

            {src, [md | maps], idx + 1}
        end)

      {cleaned, Enum.reverse(map_defs)}
    end
  end

  @doc """
  Walk a parsed AST and normalize capitalized BPF types back to lowercase.

  `:U64` → `:u64`, `:I32` → `:i32`, etc.
  """
  @spec normalize_ast(term()) :: term()
  def normalize_ast(ast) when is_list(ast) do
    Enum.map(ast, &normalize_ast/1)
  end

  # Atom wrappers from tokenizer: {:atom, :U64} → {:atom, :u64}
  def normalize_ast({:atom, val}) when is_atom(val) do
    {:atom, normalize_type_atom(val)}
  end

  # defn: normalize param types, return type, and body
  def normalize_ast({:defn, name, params, body, ret_type, loc}) do
    {:defn, name, normalize_params(params), normalize_ast(body),
     normalize_type_atom(ret_type), loc}
  end

  # defn_multi: normalize each clause
  def normalize_ast({:defn_multi, name, clauses, loc}) do
    clauses = Enum.map(clauses, fn {pattern, body} ->
      {normalize_ast(pattern), normalize_ast(body)}
    end)
    {:defn_multi, name, clauses, loc}
  end

  # deftype: normalize field types (parser wraps in {:product, fields} or {:sum, variants})
  def normalize_ast({:deftype, name, {:product, fields}, loc}) do
    {:deftype, name, {:product, normalize_fields(fields)}, loc}
  end

  def normalize_ast({:deftype, name, {:sum, variants}, loc}) do
    variants = Enum.map(variants, fn {ctor, args} ->
      {ctor, normalize_fields(args)}
    end)
    {:deftype, name, {:sum, variants}, loc}
  end

  def normalize_ast({:deftype, name, fields, loc}) do
    {:deftype, name, normalize_fields(fields), loc}
  end

  # for-range: normalize to dedicated AST node
  def normalize_ast({:call, :"for-range", [var, start, end_expr, body], loc}) do
    {:for_range, normalize_ast(var), normalize_ast(start), normalize_ast(end_expr),
     normalize_ast(body), loc}
  end

  # field_access: normalize sub-expression
  def normalize_ast({:field_access, expr, field, loc}) do
    {:field_access, normalize_ast(expr), field, loc}
  end

  # call: normalize function, args, and any type-like elements
  def normalize_ast({:call, func, args, loc}) do
    {:call, normalize_ast(func), normalize_ast(args), loc}
  end

  # if
  def normalize_ast({:if, cond_expr, then_expr, else_expr, loc}) do
    {:if, normalize_ast(cond_expr), normalize_ast(then_expr),
     normalize_ast(else_expr), loc}
  end

  # let: normalize bindings and body
  def normalize_ast({:let, bindings, body, loc}) do
    bindings = Enum.map(bindings, fn {name, expr} ->
      {normalize_ast(name), normalize_ast(expr)}
    end)
    {:let, bindings, normalize_ast(body), loc}
  end

  # match
  def normalize_ast({:match, expr, clauses, loc}) do
    clauses = Enum.map(clauses, fn {pattern, body} ->
      {normalize_ast(pattern), normalize_ast(body)}
    end)
    {:match, normalize_ast(expr), clauses, loc}
  end

  # do block
  def normalize_ast({:do, exprs, loc}) do
    {:do, normalize_ast(exprs), loc}
  end

  # fn (anonymous)
  def normalize_ast({:fn, params, body, loc}) do
    {:fn, normalize_ast(params), normalize_ast(body), loc}
  end

  # ns, import — pass through
  def normalize_ast({:ns, name, loc}), do: {:ns, name, loc}
  def normalize_ast({:import, mod, als, loc}), do: {:import, mod, als, loc}

  # extern with separate arg_types and ret_type (6-element from parser)
  # Parser produces: {:extern, mod, func, [{:atom, :U64}, ...], {:atom, :U64}, loc}
  def normalize_ast({:extern, mod, name, arg_types, ret_type, loc}) do
    norm_args = Enum.map(arg_types, &unwrap_and_normalize/1)
    {:extern, mod, name, norm_args, unwrap_and_normalize(ret_type), loc}
  end

  # extern (5-element fallback for pre-normalized forms)
  def normalize_ast({:extern, mod, name, type, loc}) do
    {:extern, mod, name, normalize_type(type), loc}
  end

  # bracket (from parser intermediate form)
  def normalize_ast({:bracket, contents}) do
    {:bracket, normalize_ast(contents)}
  end

  # cons
  def normalize_ast({:cons, head, tail, loc}) do
    {:cons, normalize_ast(head), normalize_ast(tail), loc}
  end

  # Bare atoms — normalize if they're a BPF type
  def normalize_ast(atom) when is_atom(atom), do: normalize_type_atom(atom)

  # Numbers, strings — pass through
  def normalize_ast(other), do: other

  # ============================================================================
  # Helpers
  # ============================================================================

  defp normalize_params(params) do
    Enum.map(params, fn
      {name, type} -> {name, normalize_type_atom(type)}
      other -> normalize_ast(other)
    end)
  end

  defp normalize_fields(fields) do
    Enum.map(fields, fn
      {name, {:atom, type}} -> {name, normalize_type_atom(type)}
      {name, type} when is_atom(type) -> {name, normalize_type_atom(type)}
      other -> normalize_ast(other)
    end)
  end

  # Normalize a type that might be nested: {:fn, [args], ret}, {:list, elem}, etc.
  defp normalize_type({:fn, args, ret}) do
    {:fn, Enum.map(args, &normalize_type/1), normalize_type(ret)}
  end

  defp normalize_type({:list, elem}), do: {:list, normalize_type(elem)}
  defp normalize_type(atom) when is_atom(atom), do: normalize_type_atom(atom)
  defp normalize_type(other), do: other

  # Unwrap {:atom, :U64} → :u64, or bare atom → normalized
  defp unwrap_and_normalize({:atom, val}), do: normalize_type_atom(val)
  defp unwrap_and_normalize(atom) when is_atom(atom), do: normalize_type_atom(atom)
  defp unwrap_and_normalize(other), do: other

  # Parse defmap type field: "0" → :none, other → atom
  defp parse_defmap_type("0"), do: :none
  defp parse_defmap_type(s), do: String.to_atom(s)

  # The core atom normalization: :U64 → :u64, :I32 → :i32, etc.
  defp normalize_type_atom(atom) when is_atom(atom) do
    Map.get(@normalize_map, atom, atom)
  end

  defp normalize_type_atom(other), do: other
end
