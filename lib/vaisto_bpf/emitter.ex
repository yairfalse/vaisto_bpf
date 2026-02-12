defmodule VaistoBpf.Emitter do
  @moduledoc """
  Transforms typed Vaisto AST to BPF IR (linear instructions with symbolic labels).

  The emitter handles:
  - Literals → `mov_imm reg, value`
  - Arithmetic → `alu64 op, dst, src`
  - Variables/let → register allocation (linear scan over r1-r9)
  - `if` → conditional jump with labels
  - `defn` → function body with exit

  Context tracks: next register, next label ID, variable→register map.
  """

  alias VaistoBpf.Types

  @type context :: %{
          next_reg: non_neg_integer(),
          next_label: non_neg_integer(),
          vars: %{atom() => non_neg_integer()},
          instructions: [VaistoBpf.IR.node()]
        }

  @doc """
  Emit BPF IR from a typed AST.

  Returns `{:ok, instructions}` where instructions is a list of IR nodes.
  """
  @spec emit(term()) :: {:ok, [VaistoBpf.IR.node()]} | {:error, Vaisto.Error.t()}
  def emit(ast) do
    ctx = new_context()

    try do
      {_reg, ctx} = emit_node(ast, ctx)
      {:ok, Enum.reverse(ctx.instructions)}
    rescue
      e in RuntimeError -> {:error, Vaisto.Error.new(e.message)}
    end
  end

  # ============================================================================
  # Context Management
  # ============================================================================

  defp new_context do
    %{
      next_reg: Types.r1(),
      next_label: 0,
      vars: %{},
      instructions: []
    }
  end

  defp alloc_reg(ctx) do
    reg = ctx.next_reg

    if reg > Types.r9() do
      raise "BPF register overflow — too many live values (max 9 registers)"
    end

    {reg, %{ctx | next_reg: reg + 1}}
  end

  defp alloc_label(ctx) do
    label = {:label, ctx.next_label}
    {label, %{ctx | next_label: ctx.next_label + 1}}
  end

  defp push(ctx, insn) do
    %{ctx | instructions: [insn | ctx.instructions]}
  end

  defp bind_var(ctx, name, reg) do
    %{ctx | vars: Map.put(ctx.vars, name, reg)}
  end

  # ============================================================================
  # Module / Top-Level
  # ============================================================================

  defp emit_node({:module, forms}, ctx) do
    Enum.reduce(forms, {Types.r0(), ctx}, fn form, {_reg, ctx} ->
      emit_node(form, ctx)
    end)
  end

  # Skip declarations that don't produce code
  defp emit_node({:ns, _name}, ctx), do: {Types.r0(), ctx}
  defp emit_node({:import, _mod, _alias}, ctx), do: {Types.r0(), ctx}
  defp emit_node({:extern, _mod, _name, _type}, ctx), do: {Types.r0(), ctx}
  defp emit_node({:deftype, _name, _shape, _type}, ctx), do: {Types.r0(), ctx}

  # ============================================================================
  # Function Definition
  # ============================================================================

  defp emit_node({:defn, name, params, body, _fn_type}, ctx) do
    # Emit function label
    ctx = push(ctx, {:label, {:fn, name}})

    # Bind parameters to registers r1..rN (BPF calling convention)
    {ctx, _} =
      Enum.reduce(params, {ctx, Types.r1()}, fn
        param, {ctx, reg} when is_atom(param) ->
          {bind_var(ctx, param, reg), reg + 1}
        {:var, name, _type}, {ctx, reg} ->
          {bind_var(ctx, name, reg), reg + 1}
      end)

    # Set next_reg past the parameters
    param_count = length(params)
    ctx = %{ctx | next_reg: Types.r1() + param_count}

    # Emit body — result goes to some register
    {result_reg, ctx} = emit_node(body, ctx)

    # Move result to r0 (return register) if not already there
    ctx =
      if result_reg != Types.r0() do
        push(ctx, {:mov_reg, Types.r0(), result_reg})
      else
        ctx
      end

    ctx = push(ctx, :exit)
    {Types.r0(), ctx}
  end

  # Value definition
  defp emit_node({:defval, name, expr, _type}, ctx) do
    {reg, ctx} = emit_node(expr, ctx)
    ctx = bind_var(ctx, name, reg)
    {reg, ctx}
  end

  # ============================================================================
  # Literals
  # ============================================================================

  defp emit_node({:lit, :int, value}, ctx) do
    {reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_imm, reg, value})
    {reg, ctx}
  end

  defp emit_node({:lit, :bool, true}, ctx) do
    {reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_imm, reg, 1})
    {reg, ctx}
  end

  defp emit_node({:lit, :bool, false}, ctx) do
    {reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_imm, reg, 0})
    {reg, ctx}
  end

  defp emit_node({:lit, :unit, _}, ctx) do
    {reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_imm, reg, 0})
    {reg, ctx}
  end

  defp emit_node({:lit, :atom, _val}, ctx) do
    # Atoms in BPF context are treated as integer constants (0)
    {reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_imm, reg, 0})
    {reg, ctx}
  end

  # ============================================================================
  # Variables
  # ============================================================================

  defp emit_node({:var, name, _type}, ctx) do
    case Map.fetch(ctx.vars, name) do
      {:ok, reg} -> {reg, ctx}
      :error -> raise "unbound variable: #{name}"
    end
  end

  defp emit_node({:fn_ref, _name, _arity, _type}, ctx) do
    # Function references in BPF context — not directly usable
    {Types.r0(), ctx}
  end

  # ============================================================================
  # Arithmetic
  # ============================================================================

  @alu_ops %{
    :+ => :add,
    :- => :sub,
    :* => :mul,
    :div => :div,
    :rem => :mod,
    :band => :and,
    :bor => :or,
    :bxor => :xor,
    :bsl => :lsh,
    :bsr => :rsh
  }

  @comparison_ops %{
    :== => :jeq,
    :!= => :jne,
    :> => :jgt,
    :>= => :jge,
    :< => :jlt,
    :<= => :jle
  }

  defp emit_node({:call, op, [left, right], ret_type}, ctx) when is_map_key(@alu_ops, op) do
    alu_op = Map.fetch!(@alu_ops, op)
    {left_reg, ctx} = emit_node(left, ctx)

    case right do
      {:lit, :int, imm} ->
        # Optimize: use immediate form
        {dst, ctx} = alloc_reg(ctx)
        ctx = push(ctx, {:mov_reg, dst, left_reg})
        ctx = push(ctx, alu_insn(alu_op, :imm, dst, imm, ret_type))
        {dst, ctx}

      _ ->
        {right_reg, ctx} = emit_node(right, ctx)
        {dst, ctx} = alloc_reg(ctx)
        ctx = push(ctx, {:mov_reg, dst, left_reg})
        ctx = push(ctx, alu_insn(alu_op, :reg, dst, right_reg, ret_type))
        {dst, ctx}
    end
  end

  # Negation (unary -)
  defp emit_node({:call, :-, [operand], _ret_type}, ctx) do
    {src_reg, ctx} = emit_node(operand, ctx)
    {dst, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_imm, dst, 0})
    ctx = push(ctx, {:alu64_reg, :sub, dst, src_reg})
    {dst, ctx}
  end

  # Comparison operations — produce 0 or 1
  defp emit_node({:call, op, [left, right], _ret_type}, ctx)
       when is_map_key(@comparison_ops, op) do
    jmp_op = Map.fetch!(@comparison_ops, op)
    {left_reg, ctx} = emit_node(left, ctx)
    {right_reg, ctx} = emit_node(right, ctx)
    {result_reg, ctx} = alloc_reg(ctx)
    {true_label, ctx} = alloc_label(ctx)
    {end_label, ctx} = alloc_label(ctx)

    # result = 0; if left OP right goto true; goto end; true: result = 1; end:
    ctx = push(ctx, {:mov_imm, result_reg, 0})
    ctx = push(ctx, {:jmp_reg, jmp_op, left_reg, right_reg, true_label})
    ctx = push(ctx, {:ja, end_label})
    ctx = push(ctx, {:label, true_label})
    ctx = push(ctx, {:mov_imm, result_reg, 1})
    ctx = push(ctx, {:label, end_label})

    {result_reg, ctx}
  end

  # Boolean not
  defp emit_node({:call, :not, [operand], _type}, ctx) do
    {src, ctx} = emit_node(operand, ctx)
    {dst, ctx} = alloc_reg(ctx)
    # not x = x XOR 1
    ctx = push(ctx, {:mov_reg, dst, src})
    ctx = push(ctx, {:alu64_imm, :xor, dst, 1})
    {dst, ctx}
  end

  # BPF helper call: (bpf/ktime_get_ns), (bpf/map_lookup_elem fd key)
  defp emit_node({:call, {:qualified, :bpf, helper_name}, args, _ret_type}, ctx) do
    helper_id = VaistoBpf.Helpers.helper_id!(helper_name)

    # 1. Evaluate all args into temporary registers first
    {arg_regs, ctx} =
      Enum.map_reduce(args, ctx, fn arg, ctx ->
        emit_node(arg, ctx)
      end)

    # 2. Spill any live variables in r1-r5 to callee-saved regs (r6-r9)
    {ctx, restore_map} = spill_caller_saved(ctx)

    # 3. Remap arg_regs: if an arg was in a spilled register, read from
    #    the callee-saved copy instead (avoids register-move cycle bugs)
    arg_regs = Enum.map(arg_regs, fn reg -> Map.get(restore_map, reg, reg) end)

    # 4. Move evaluated args to r1-r5 (BPF calling convention)
    ctx =
      arg_regs
      |> Enum.with_index(Types.r1())
      |> Enum.reduce(ctx, fn {src_reg, dst_reg}, ctx ->
        if src_reg == dst_reg, do: ctx, else: push(ctx, {:mov_reg, dst_reg, src_reg})
      end)

    # 5. Emit call
    ctx = push(ctx, {:call, helper_id})

    # 6. Copy result from r0 to an allocated register
    {result_reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_reg, result_reg, Types.r0()})

    # Variables were already rebound to callee-saved locations during spill

    {result_reg, ctx}
  end

  # Generic call (catch-all for builtins we don't special-case)
  defp emit_node({:call, _op, args, _ret_type}, ctx) do
    # Emit all args, return the last one (placeholder for unknown ops)
    {last_reg, ctx} =
      Enum.reduce(args, {Types.r0(), ctx}, fn arg, {_reg, ctx} ->
        emit_node(arg, ctx)
      end)

    {last_reg, ctx}
  end


  # ============================================================================
  # Control Flow
  # ============================================================================

  defp emit_node({:if, cond_expr, then_expr, else_expr, _type}, ctx) do
    {cond_reg, ctx} = emit_node(cond_expr, ctx)
    {else_label, ctx} = alloc_label(ctx)
    {end_label, ctx} = alloc_label(ctx)
    {result_reg, ctx} = alloc_reg(ctx)

    # if cond_reg == 0 goto else
    ctx = push(ctx, {:jmp_imm, :jeq, cond_reg, 0, else_label})

    # then branch
    {then_reg, ctx} = emit_node(then_expr, ctx)
    ctx = push(ctx, {:mov_reg, result_reg, then_reg})
    ctx = push(ctx, {:ja, end_label})

    # else branch
    ctx = push(ctx, {:label, else_label})
    {else_reg, ctx} = emit_node(else_expr, ctx)
    ctx = push(ctx, {:mov_reg, result_reg, else_reg})

    # end
    ctx = push(ctx, {:label, end_label})

    {result_reg, ctx}
  end

  # let bindings
  defp emit_node({:let, bindings, body, _type}, ctx) do
    ctx =
      Enum.reduce(bindings, ctx, fn
        {{:var, name, _type}, expr}, ctx ->
          {reg, ctx} = emit_node(expr, ctx)
          bind_var(ctx, name, reg)

        {name, expr}, ctx when is_atom(name) ->
          {reg, ctx} = emit_node(expr, ctx)
          bind_var(ctx, name, reg)
      end)

    emit_node(body, ctx)
  end

  # match expressions (simple: pattern → body)
  defp emit_node({:match, expr, clauses, _type}, ctx) do
    {expr_reg, ctx} = emit_node(expr, ctx)
    {result_reg, ctx} = alloc_reg(ctx)
    {end_label, ctx} = alloc_label(ctx)

    {ctx, _} =
      Enum.reduce(clauses, {ctx, 0}, fn {pattern, body, _clause_type}, {ctx, idx} ->
        {next_label, ctx} = alloc_label(ctx)

        # Bind pattern variables or emit comparison
        ctx = emit_pattern_check(pattern, expr_reg, next_label, ctx)

        # Emit body
        {body_reg, ctx} = emit_node(body, ctx)
        ctx = push(ctx, {:mov_reg, result_reg, body_reg})
        ctx = push(ctx, {:ja, end_label})

        # Next clause
        ctx = push(ctx, {:label, next_label})
        {ctx, idx + 1}
      end)

    ctx = push(ctx, {:label, end_label})
    {result_reg, ctx}
  end

  # do block
  defp emit_node({:do, exprs, _type}, ctx) do
    Enum.reduce(exprs, {Types.r0(), ctx}, fn expr, {_reg, ctx} ->
      emit_node(expr, ctx)
    end)
  end

  # Field access — placeholder (would need layout info for real offset calculation)
  defp emit_node({:field_access, expr, _field, _type}, ctx) do
    emit_node(expr, ctx)
  end

  defp emit_node({:field_access, expr, _field, _record_type, _type}, ctx) do
    emit_node(expr, ctx)
  end

  # ============================================================================
  # Pattern Matching Helpers
  # ============================================================================

  defp emit_pattern_check({:lit, :int, value}, expr_reg, fail_label, ctx) do
    # if expr_reg != value goto fail
    push(ctx, {:jmp_imm, :jne, expr_reg, value, fail_label})
  end

  defp emit_pattern_check({:var, name, _type}, expr_reg, _fail_label, ctx) do
    # Bind variable to the expression register
    bind_var(ctx, name, expr_reg)
  end

  defp emit_pattern_check(:_, _expr_reg, _fail_label, ctx) do
    # Wildcard — always matches
    ctx
  end

  defp emit_pattern_check(_pattern, _expr_reg, _fail_label, ctx) do
    # Catch-all: skip pattern check (will match anything)
    ctx
  end

  # ============================================================================
  # Helper Call Register Spilling
  # ============================================================================

  # BPF calling convention: r1-r5 are caller-saved (clobbered by helper calls).
  # Before a helper call, we must save any live variables in r1-r5 to
  # callee-saved registers r6-r9. After the call, variable lookups use
  # the new locations.
  #
  # Returns {updated_ctx, restore_map} where restore_map is %{old_reg => new_reg}
  defp spill_caller_saved(ctx) do
    # Find variables currently mapped to r1-r5
    vars_in_caller_saved =
      ctx.vars
      |> Enum.filter(fn {_name, reg} -> reg >= Types.r1() and reg <= Types.r5() end)
      |> Enum.sort_by(fn {_name, reg} -> reg end)

    if vars_in_caller_saved == [] do
      {ctx, %{}}
    else
      # Allocate callee-saved regs (r6-r9) for spilling
      available = callee_saved_available(ctx)

      if length(vars_in_caller_saved) > length(available) do
        raise "too many live values across helper call (max #{length(available)} callee-saved registers available)"
      end

      {ctx, restore_map} =
        Enum.zip(vars_in_caller_saved, available)
        |> Enum.reduce({ctx, %{}}, fn {{var_name, old_reg}, save_reg}, {ctx, rmap} ->
          ctx = push(ctx, {:mov_reg, save_reg, old_reg})
          ctx = bind_var(ctx, var_name, save_reg)
          {ctx, Map.put(rmap, old_reg, save_reg)}
        end)

      # Ensure next_reg stays past any callee-saved regs we used
      max_used = available |> Enum.take(length(vars_in_caller_saved)) |> Enum.max()
      ctx = %{ctx | next_reg: max(ctx.next_reg, max_used + 1)}

      {ctx, restore_map}
    end
  end

  # Returns list of callee-saved registers (r6-r9) not currently in use
  defp callee_saved_available(ctx) do
    used = ctx.vars |> Map.values() |> MapSet.new()
    Enum.reject(Types.r6()..Types.r9(), &MapSet.member?(used, &1))
  end

  # ============================================================================
  # ALU Instruction Helpers
  # ============================================================================

  defp alu_insn(op, :imm, dst, imm, type) do
    if is_64bit?(type), do: {:alu64_imm, op, dst, imm}, else: {:alu32_imm, op, dst, imm}
  end

  defp alu_insn(op, :reg, dst, src, type) do
    if is_64bit?(type), do: {:alu64_reg, op, dst, src}, else: {:alu32_reg, op, dst, src}
  end

  defp is_64bit?(type) when type in [:u64, :i64], do: true
  defp is_64bit?({:fn, _, ret}), do: is_64bit?(ret)
  defp is_64bit?(_), do: false
end
