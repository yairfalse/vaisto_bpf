defmodule VaistoBpf.Emitter do
  @moduledoc """
  Transforms typed Vaisto AST to BPF IR (linear instructions with symbolic labels).

  The emitter handles:
  - Literals → `mov_imm reg, value`
  - Arithmetic → `alu64 op, dst, src`
  - Variables/let → register allocation (free-list over r1-r9)
  - `if` → conditional jump with labels
  - `defn` → function body with exit

  Context tracks: free register list, next label ID, variable→register map.
  """

  alias VaistoBpf.Types

  @type context :: %{
          free_regs: [non_neg_integer()],
          next_label: non_neg_integer(),
          vars: %{atom() => non_neg_integer()},
          instructions: [VaistoBpf.IR.node()]
        }

  @doc """
  Emit BPF IR from a typed AST.

  Accepts an optional list of `%MapDef{}` structs. When a variable references
  a map name, the emitter generates `ld_map_fd` instead of a register lookup.

  Returns `{:ok, instructions}` where instructions is a list of IR nodes.
  """
  @spec emit(term(), [VaistoBpf.MapDef.t()]) :: {:ok, [VaistoBpf.IR.node()]} | {:error, Vaisto.Error.t()}
  def emit(ast, maps \\ []) do
    ctx = new_context(maps)

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

  defp new_context(maps) do
    map_lookup = Map.new(maps, fn md -> {md.name, md.index} end)
    %{
      free_regs: Enum.to_list(Types.r1()..Types.r9()),
      next_label: 0,
      vars: %{},
      instructions: [],
      maps: map_lookup,
      stack_offset: 0
    }
  end

  defp alloc_stack_slot(ctx, byte_size) do
    aligned = VaistoBpf.Layout.align_up(byte_size, 8)
    offset = ctx.stack_offset - aligned

    if offset < -512 do
      raise "BPF stack overflow (max 512 bytes)"
    end

    {offset, %{ctx | stack_offset: offset}}
  end

  defp alloc_reg(ctx) do
    case ctx.free_regs do
      [reg | rest] -> {reg, %{ctx | free_regs: rest}}
      [] -> raise "BPF register overflow — too many live values (max 9 registers)"
    end
  end

  @r1 Types.r1()
  @r9 Types.r9()

  defp free_reg(ctx, reg) when reg >= @r1 and reg <= @r9 do
    if reg in ctx.free_regs, do: ctx, else: %{ctx | free_regs: Enum.sort([reg | ctx.free_regs])}
  end
  defp free_reg(ctx, _reg), do: ctx

  defp maybe_free_reg(ctx, reg) do
    if reg in Map.values(ctx.vars), do: ctx, else: free_reg(ctx, reg)
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
    param_count = length(params)
    param_regs = if param_count > 0, do: Enum.to_list(Types.r1()..(Types.r1() + param_count - 1)), else: []

    {ctx, _} =
      Enum.reduce(params, {ctx, Types.r1()}, fn
        param, {ctx, reg} when is_atom(param) ->
          {bind_var(ctx, param, reg), reg + 1}
        {:var, name, _type}, {ctx, reg} ->
          {bind_var(ctx, name, reg), reg + 1}
      end)

    # Remove parameter registers from free list
    ctx = %{ctx | free_regs: ctx.free_regs -- param_regs}

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
    case Map.fetch(ctx.maps, name) do
      {:ok, map_index} ->
        # Map reference: emit LD_IMM64 with pseudo-map-FD
        {reg, ctx} = alloc_reg(ctx)
        ctx = push(ctx, {:ld_map_fd, reg, map_index})
        {reg, ctx}

      :error ->
        case Map.fetch(ctx.vars, name) do
          {:ok, reg} -> {reg, ctx}
          :error -> raise "unbound variable: #{name}"
        end
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
        ctx = maybe_free_reg(ctx, left_reg)
        {dst, ctx} = alloc_reg(ctx)
        ctx = push(ctx, {:mov_reg, dst, left_reg})
        ctx = push(ctx, alu_insn(alu_op, :imm, dst, imm, ret_type))
        {dst, ctx}

      _ ->
        {right_reg, ctx} = emit_node(right, ctx)
        ctx = maybe_free_reg(ctx, left_reg)
        ctx = maybe_free_reg(ctx, right_reg)
        {dst, ctx} = alloc_reg(ctx)
        ctx = push(ctx, {:mov_reg, dst, left_reg})
        ctx = push(ctx, alu_insn(alu_op, :reg, dst, right_reg, ret_type))
        {dst, ctx}
    end
  end

  # Negation (unary -)
  defp emit_node({:call, :-, [operand], _ret_type}, ctx) do
    {src_reg, ctx} = emit_node(operand, ctx)
    ctx = maybe_free_reg(ctx, src_reg)
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
    ctx = maybe_free_reg(ctx, left_reg)
    ctx = maybe_free_reg(ctx, right_reg)
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
    ctx = maybe_free_reg(ctx, src)
    {dst, ctx} = alloc_reg(ctx)
    # not x = x XOR 1
    ctx = push(ctx, {:mov_reg, dst, src})
    ctx = push(ctx, {:alu64_imm, :xor, dst, 1})
    {dst, ctx}
  end

  # BPF qualified call: memory builtins or helper calls
  defp emit_node({:call, {:qualified, :bpf, helper_name}, args, _ret_type}, ctx) do
    case memory_builtin(helper_name) do
      {:load, size} -> emit_load(size, args, ctx)
      {:store, size} -> emit_store(size, args, ctx)
      {:stack_store, size} -> emit_stack_store(size, args, ctx)
      {:stack_load, size} -> emit_stack_load(size, args, ctx)
      nil -> emit_helper_call(helper_name, args, ctx)
    end
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
    ctx = maybe_free_reg(ctx, cond_reg)
    {else_label, ctx} = alloc_label(ctx)
    {end_label, ctx} = alloc_label(ctx)
    {result_reg, ctx} = alloc_reg(ctx)

    # if cond_reg == 0 goto else
    ctx = push(ctx, {:jmp_imm, :jeq, cond_reg, 0, else_label})

    # then branch
    {then_reg, ctx} = emit_node(then_expr, ctx)
    ctx = push(ctx, {:mov_reg, result_reg, then_reg})
    ctx = maybe_free_reg(ctx, then_reg)
    ctx = push(ctx, {:ja, end_label})

    # else branch
    ctx = push(ctx, {:label, else_label})
    {else_reg, ctx} = emit_node(else_expr, ctx)
    ctx = push(ctx, {:mov_reg, result_reg, else_reg})
    ctx = maybe_free_reg(ctx, else_reg)

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
        ctx = maybe_free_reg(ctx, body_reg)
        ctx = push(ctx, {:ja, end_label})

        # Next clause
        ctx = push(ctx, {:label, next_label})
        {ctx, idx + 1}
      end)

    ctx = maybe_free_reg(ctx, expr_reg)
    ctx = push(ctx, {:label, end_label})
    {result_reg, ctx}
  end

  # do block
  defp emit_node({:do, exprs, _type}, ctx) do
    Enum.reduce(exprs, {Types.r0(), ctx}, fn expr, {prev_reg, ctx} ->
      ctx = maybe_free_reg(ctx, prev_reg)
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

  # Some pattern: non-null check — if ptr == 0, jump to next clause
  defp emit_pattern_check({:some_pattern, {:var, name, _type}}, expr_reg, fail_label, ctx) do
    ctx = push(ctx, {:jmp_imm, :jeq, expr_reg, 0, fail_label})
    bind_var(ctx, name, expr_reg)
  end

  # None pattern: null check — if ptr != 0, jump to next clause
  defp emit_pattern_check(:none_pattern, expr_reg, fail_label, ctx) do
    push(ctx, {:jmp_imm, :jne, expr_reg, 0, fail_label})
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
  # Memory Access Builtins (inline LDX_MEM / STX_MEM)
  # ============================================================================

  @memory_load_builtins %{
    load_u8: :u8, load_u16: :u16, load_u32: :u32, load_u64: :u64
  }

  @memory_store_builtins %{
    store_u8: :u8, store_u16: :u16, store_u32: :u32, store_u64: :u64
  }

  @stack_store_builtins %{
    stack_store_u64: :u64, stack_store_u32: :u32
  }

  @stack_load_builtins %{
    stack_load_u64: :u64, stack_load_u32: :u32
  }

  defp memory_builtin(name) do
    cond do
      size = Map.get(@memory_load_builtins, name) -> {:load, size}
      size = Map.get(@memory_store_builtins, name) -> {:store, size}
      size = Map.get(@stack_store_builtins, name) -> {:stack_store, size}
      size = Map.get(@stack_load_builtins, name) -> {:stack_load, size}
      true -> nil
    end
  end

  defp emit_load(size, [ptr_expr, offset_expr], ctx) do
    {ptr_reg, ctx} = emit_node(ptr_expr, ctx)
    offset = extract_literal_offset!(offset_expr)
    ctx = maybe_free_reg(ctx, ptr_reg)
    {dst, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:ldx_mem, size, dst, ptr_reg, offset})
    {dst, ctx}
  end

  defp emit_store(size, [ptr_expr, offset_expr, val_expr], ctx) do
    {ptr_reg, ctx} = emit_node(ptr_expr, ctx)
    offset = extract_literal_offset!(offset_expr)
    {val_reg, ctx} = emit_node(val_expr, ctx)
    ctx = push(ctx, {:stx_mem, size, ptr_reg, val_reg, offset})
    ctx = maybe_free_reg(ctx, val_reg)
    {ptr_reg, ctx}
  end

  defp emit_stack_store(size, [offset_expr, val_expr], ctx) do
    offset = extract_literal_offset!(offset_expr)
    {val_reg, ctx} = emit_node(val_expr, ctx)
    ctx = push(ctx, {:stx_mem, size, Types.r10(), val_reg, offset})
    ctx = maybe_free_reg(ctx, val_reg)
    {val_reg, ctx}
  end

  defp emit_stack_load(size, [offset_expr], ctx) do
    offset = extract_literal_offset!(offset_expr)
    {dst, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:ldx_mem, size, dst, Types.r10(), offset})
    {dst, ctx}
  end

  defp extract_literal_offset!({:lit, :int, value}) when is_integer(value), do: value
  defp extract_literal_offset!(other) do
    raise "memory access offset must be a compile-time literal, got: #{inspect(other)}"
  end

  # ============================================================================
  # BPF Helper Call Emission
  # ============================================================================

  defp emit_helper_call(helper_name, args, ctx) do
    helper_id = VaistoBpf.Helpers.helper_id!(helper_name)
    ptr_arg_indices = VaistoBpf.Helpers.ptr_args(helper_name)

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

    # 4. Free arg temp registers (they're consumed by place_args)
    ctx = Enum.reduce(arg_regs, ctx, fn reg, ctx -> maybe_free_reg(ctx, reg) end)

    # 5. Place args: merge ptr_args spill + move to r1-r5
    ctx = place_args(arg_regs, ptr_arg_indices, ctx)

    # 6. Emit call
    ctx = push(ctx, {:call, helper_id})

    # 6. Reclaim r1-r5 BEFORE alloc (they're dead after call)
    ctx = reclaim_registers(ctx)

    # 7. Copy result from r0 to an allocated register
    {result_reg, ctx} = alloc_reg(ctx)
    ctx = push(ctx, {:mov_reg, result_reg, Types.r0()})

    {result_reg, ctx}
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
      # Allocate callee-saved regs (r6-r9) from the free list
      available = Enum.filter(ctx.free_regs, &(&1 >= Types.r6() and &1 <= Types.r9()))

      if length(vars_in_caller_saved) > length(available) do
        raise "too many live values across helper call (max #{length(available)} callee-saved registers available)"
      end

      {ctx, restore_map} =
        Enum.zip(vars_in_caller_saved, available)
        |> Enum.reduce({ctx, %{}}, fn {{var_name, old_reg}, save_reg}, {ctx, rmap} ->
          ctx = push(ctx, {:mov_reg, save_reg, old_reg})
          ctx = bind_var(ctx, var_name, save_reg)
          # Remove save_reg from free list (now in use), add old_reg back (no longer bound)
          ctx = %{ctx | free_regs: Enum.sort([old_reg | ctx.free_regs -- [save_reg]])}
          {ctx, Map.put(rmap, old_reg, save_reg)}
        end)

      {ctx, restore_map}
    end
  end

  # After a helper call, r1-r5 are dead (clobbered by calling convention).
  # Add r1-r5 back to the free list, skipping any still bound to variables.
  defp reclaim_registers(ctx) do
    bound = Map.values(ctx.vars) |> MapSet.new()
    freed = Enum.reject(Types.r1()..Types.r5(), &MapSet.member?(bound, &1))
    %{ctx | free_regs: Enum.sort(Enum.uniq(freed ++ ctx.free_regs))}
  end

  # Merged arg placement: moves args to r1-r5, computing stack pointers
  # directly in the target register for ptr_args (no temp register needed).
  defp place_args(arg_regs, ptr_indices, ctx) do
    arg_regs
    |> Enum.with_index()
    |> Enum.reduce(ctx, fn {src_reg, idx}, ctx ->
      dst_reg = Types.r1() + idx

      if idx in ptr_indices do
        # Store value to stack, compute pointer directly in target register
        {offset, ctx} = alloc_stack_slot(ctx, 8)
        ctx = push(ctx, {:stx_mem, :u64, Types.r10(), src_reg, offset})
        ctx = push(ctx, {:mov_reg, dst_reg, Types.r10()})
        push(ctx, {:alu64_imm, :add, dst_reg, offset})
      else
        if src_reg == dst_reg, do: ctx, else: push(ctx, {:mov_reg, dst_reg, src_reg})
      end
    end)
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
