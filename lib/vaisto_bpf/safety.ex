defmodule VaistoBpf.Safety do
  @moduledoc """
  Static safety analysis pass for BPF programs.

  Catches BPF-fatal errors at compile time — before the kernel verifier —
  providing clear, actionable error messages instead of cryptic verifier
  rejections or runtime faults.

  Runs post-type-check, pre-emit: the input is a fully-typed AST.
  """

  alias VaistoBpf.Types

  @doc """
  Check a typed AST for statically-detectable BPF safety violations.

  Returns `:ok` or `{:error, %Vaisto.Error{}}`.
  Warnings (e.g. dead loops) are collected but don't fail the check.
  """
  # BPF limits BPF-to-BPF call depth
  @max_call_depth 8

  @spec check(term()) :: :ok | {:error, Vaisto.Error.t()}
  def check(typed_ast) do
    with :ok <- check_call_depth(typed_ast) do
      case walk(typed_ast, []) do
        {[], _warnings} -> :ok
        {[error | _], _warnings} -> {:error, Vaisto.Error.new(error)}
      end
    end
  end

  @doc """
  Like `check/1` but returns `{:ok, warnings}` on success, where warnings
  is a list of `{:warning, message}` tuples.
  """
  @spec check_with_warnings(term()) :: {:ok, [{:warning, String.t()}]} | {:error, Vaisto.Error.t()}
  def check_with_warnings(typed_ast) do
    case walk(typed_ast, []) do
      {[], warnings} -> {:ok, warnings}
      {[error | _], _warnings} -> {:error, Vaisto.Error.new(error)}
    end
  end

  # Walk returns {errors, warnings}
  defp walk(node, warnings) do
    case check_node(node) do
      {:error, msg} -> {[msg], warnings}
      {:warning, msg} -> walk_children(node, [{:warning, msg} | warnings])
      :ok -> walk_children(node, warnings)
    end
  end

  # --- Check individual nodes ---

  # A1. Division/modulo by literal zero
  defp check_node({:call, :div, [_, {:lit, :int, 0}], _type}),
    do: {:error, "division by zero: divisor is literal 0"}

  defp check_node({:call, :rem, [_, {:lit, :int, 0}], _type}),
    do: {:error, "division by zero: divisor is literal 0"}

  # A3. Shift amount validation
  defp check_node({:call, op, [_, {:lit, :int, amount}], ret_type})
       when op in [:bsl, :bsr] do
    width = type_width_bits(ret_type)

    cond do
      width == nil -> :ok
      amount < 0 -> {:error, "shift amount #{amount} is negative"}
      amount >= width -> {:error, "shift amount #{amount} exceeds type width of #{width} bits"}
      true -> :ok
    end
  end

  # A2. Field access offset bounds (checked via field_access node)
  # The type checker already validates field existence, so field_access with
  # a known record type is safe. We could add checks for raw pointer arithmetic
  # with literal offsets here in the future.

  # A4. Negative/empty loop bounds
  defp check_node({:for_range, _var, {:lit, :int, start}, {:lit, :int, end_val}, _body, _type})
       when start >= end_val do
    {:warning, "for-range loop from #{start} to #{end_val} will never execute (start >= end)"}
  end

  defp check_node(_), do: :ok

  # --- Walk children ---

  defp walk_children({:call, {:qualified, _, _}, args, _type}, warnings) do
    walk_list(args, warnings)
  end

  defp walk_children({:call, _op, args, _type}, warnings) do
    walk_list(args, warnings)
  end

  defp walk_children({:let, bindings, body}, warnings) do
    {errors, warnings} = walk_bindings(bindings, warnings)
    if errors != [], do: {errors, warnings}, else: walk(body, warnings)
  end

  defp walk_children({:let, bindings, body, _type}, warnings) do
    {errors, warnings} = walk_bindings(bindings, warnings)
    if errors != [], do: {errors, warnings}, else: walk(body, warnings)
  end

  defp walk_children({:do, exprs}, warnings) do
    walk_list(exprs, warnings)
  end

  defp walk_children({:if, cond_expr, then_expr, else_expr, _type}, warnings) do
    with {[], warnings} <- walk(cond_expr, warnings),
         {[], warnings} <- walk(then_expr, warnings),
         {[], warnings} <- walk(else_expr, warnings) do
      {[], warnings}
    end
  end

  defp walk_children({:for_range, _var, start, end_expr, body, _type}, warnings) do
    with {[], warnings} <- walk(start, warnings),
         {[], warnings} <- walk(end_expr, warnings),
         {[], warnings} <- walk(body, warnings) do
      {[], warnings}
    end
  end

  defp walk_children({:match, scrutinee, clauses, _type}, warnings) do
    case walk(scrutinee, warnings) do
      {[], warnings} -> walk_match_clauses(clauses, warnings)
      result -> result
    end
  end

  defp walk_children({:field_access, expr, _field, _type, _record}, warnings) do
    walk(expr, warnings)
  end

  defp walk_children({:field_access, expr, _field, _type}, warnings) do
    walk(expr, warnings)
  end

  defp walk_children({:defn, _name, _params, body, _ret_type}, warnings) do
    walk(body, warnings)
  end

  defp walk_children({:fn, _params, body, _type}, warnings) do
    walk(body, warnings)
  end

  # Leaves
  defp walk_children({:lit, _, _}, warnings), do: {[], warnings}
  defp walk_children({:var, _, _}, warnings), do: {[], warnings}
  defp walk_children({:unit}, warnings), do: {[], warnings}

  # Top-level program with multiple definitions
  defp walk_children(list, warnings) when is_list(list) do
    walk_list(list, warnings)
  end

  # Fallback — unknown node shape, don't crash
  defp walk_children(_other, warnings), do: {[], warnings}

  # --- Helpers ---

  defp walk_list(items, warnings) do
    Enum.reduce_while(items, {[], warnings}, fn item, {[], warnings} ->
      case walk(item, warnings) do
        {[], warnings} -> {:cont, {[], warnings}}
        {errors, warnings} -> {:halt, {errors, warnings}}
      end
    end)
  end

  defp walk_bindings(bindings, warnings) do
    Enum.reduce_while(bindings, {[], warnings}, fn binding, {[], warnings} ->
      expr = case binding do
        {_name, expr} -> expr
        {{:var, _, _}, expr} -> expr
      end

      case walk(expr, warnings) do
        {[], warnings} -> {:cont, {[], warnings}}
        {errors, warnings} -> {:halt, {errors, warnings}}
      end
    end)
  end

  defp walk_match_clauses(clauses, warnings) do
    Enum.reduce_while(clauses, {[], warnings}, fn clause, {[], warnings} ->
      body = case clause do
        {_pattern, body, _type} -> body
        {_pattern, body} -> body
      end

      case walk(body, warnings) do
        {[], warnings} -> {:cont, {[], warnings}}
        {errors, warnings} -> {:halt, {errors, warnings}}
      end
    end)
  end

  defp type_width_bits(type) when type in [:u8, :i8, :u16, :i16, :u32, :i32, :u64, :i64] do
    Types.width_bits(type)
  end

  defp type_width_bits(:bool), do: 8
  defp type_width_bits(_), do: nil

  # ============================================================================
  # Call Depth Analysis
  # ============================================================================

  # Extract defn forms from typed AST
  defp extract_defns({:module, forms}) when is_list(forms), do: extract_defns(forms)

  defp extract_defns(forms) when is_list(forms) do
    for {:defn, name, _params, body, _type} <- forms, do: {name, body}
  end

  defp extract_defns({:defn, name, _params, body, _type}), do: [{name, body}]
  defp extract_defns(_), do: []

  # Check that no call chain exceeds @max_call_depth
  defp check_call_depth(typed_ast) do
    defns = extract_defns(typed_ast)

    case defns do
      [] -> :ok
      [_single] -> :ok
      defns ->
        fn_names = MapSet.new(defns, fn {name, _} -> name end)
        call_graph = build_call_graph(defns, fn_names)
        max_depth = max_call_chain_depth(call_graph, fn_names)

        if max_depth > @max_call_depth do
          {:error,
           Vaisto.Error.new(
             "BPF-to-BPF call depth #{max_depth} exceeds maximum of #{@max_call_depth}"
           )}
        else
          :ok
        end
    end
  end

  defp build_call_graph(defns, fn_names) do
    Map.new(defns, fn {name, body} ->
      callees = collect_callees(body, fn_names)
      {name, callees}
    end)
  end

  defp collect_callees(node, fn_names) do
    collect_callees(node, fn_names, MapSet.new())
  end

  defp collect_callees({:call, name, args, _type}, fn_names, acc) when is_atom(name) do
    acc = if MapSet.member?(fn_names, name), do: MapSet.put(acc, name), else: acc
    Enum.reduce(args, acc, &collect_callees(&1, fn_names, &2))
  end

  defp collect_callees({:call, _op, args, _type}, fn_names, acc) do
    Enum.reduce(args, acc, &collect_callees(&1, fn_names, &2))
  end

  defp collect_callees({:if, cond_e, then_e, else_e, _type}, fn_names, acc) do
    acc = collect_callees(cond_e, fn_names, acc)
    acc = collect_callees(then_e, fn_names, acc)
    collect_callees(else_e, fn_names, acc)
  end

  defp collect_callees({:let, bindings, body}, fn_names, acc) do
    acc = reduce_bindings(bindings, fn_names, acc)
    collect_callees(body, fn_names, acc)
  end

  defp collect_callees({:let, bindings, body, _type}, fn_names, acc) do
    acc = reduce_bindings(bindings, fn_names, acc)
    collect_callees(body, fn_names, acc)
  end

  defp collect_callees({:for_range, _var, start, end_e, body, _type}, fn_names, acc) do
    acc = collect_callees(start, fn_names, acc)
    acc = collect_callees(end_e, fn_names, acc)
    collect_callees(body, fn_names, acc)
  end

  defp collect_callees({:match, scrutinee, clauses, _type}, fn_names, acc) do
    acc = collect_callees(scrutinee, fn_names, acc)
    Enum.reduce(clauses, acc, fn clause, acc ->
      body = case clause do
        {_pat, body, _type} -> body
        {_pat, body} -> body
      end
      collect_callees(body, fn_names, acc)
    end)
  end

  defp collect_callees({:do, exprs}, fn_names, acc) do
    Enum.reduce(exprs, acc, &collect_callees(&1, fn_names, &2))
  end

  defp collect_callees(_leaf, _fn_names, acc), do: acc

  defp reduce_bindings(bindings, fn_names, acc) do
    Enum.reduce(bindings, acc, fn binding, acc ->
      expr = case binding do
        {_name, expr} -> expr
        {{:var, _, _}, expr} -> expr
      end
      collect_callees(expr, fn_names, acc)
    end)
  end

  # Compute max call chain depth via DFS with cycle detection
  defp max_call_chain_depth(call_graph, fn_names) do
    fn_names
    |> Enum.map(fn name -> call_depth(name, call_graph, MapSet.new()) end)
    |> Enum.max(fn -> 0 end)
  end

  defp call_depth(name, call_graph, visited) do
    if MapSet.member?(visited, name) do
      # Cycle — return a high value to trigger the error
      @max_call_depth + 1
    else
      callees = Map.get(call_graph, name, MapSet.new())
      visited = MapSet.put(visited, name)

      if MapSet.size(callees) == 0 do
        0
      else
        1 + (callees |> Enum.map(&call_depth(&1, call_graph, visited)) |> Enum.max())
      end
    end
  end
end
