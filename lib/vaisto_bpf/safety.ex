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
  @spec check(term()) :: :ok | {:error, Vaisto.Error.t()}
  def check(typed_ast) do
    case walk(typed_ast, []) do
      {[], _warnings} -> :ok
      {[error | _], _warnings} -> {:error, Vaisto.Error.new(error)}
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
    Enum.reduce_while(bindings, {[], warnings}, fn {_name, expr}, {[], warnings} ->
      case walk(expr, warnings) do
        {[], warnings} -> {:cont, {[], warnings}}
        {errors, warnings} -> {:halt, {errors, warnings}}
      end
    end)
  end

  defp walk_match_clauses(clauses, warnings) do
    Enum.reduce_while(clauses, {[], warnings}, fn {_pattern, body}, {[], warnings} ->
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
end
