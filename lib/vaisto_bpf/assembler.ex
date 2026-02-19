defmodule VaistoBpf.Assembler do
  @moduledoc """
  Converts BPF IR to binary instruction sequences.

  Two-pass assembly:
  1. Calculate label positions (instruction indices)
  2. Emit 8-byte instructions with resolved jump offsets

  Jump offsets in BPF are relative to the instruction *after* the jump,
  measured in instruction count (not bytes).
  """

  alias VaistoBpf.Types

  @alu_op_map %{
    add: Types.alu_add(),
    sub: Types.alu_sub(),
    mul: Types.alu_mul(),
    div: Types.alu_div(),
    mod: Types.alu_mod(),
    or: Types.alu_or(),
    and: Types.alu_and(),
    xor: Types.alu_xor(),
    lsh: Types.alu_lsh(),
    rsh: Types.alu_rsh(),
    neg: Types.alu_neg(),
    mov: Types.alu_mov(),
    arsh: Types.alu_arsh()
  }

  @jmp_op_map %{
    jeq: Types.jmp_jeq(),
    jgt: Types.jmp_jgt(),
    jge: Types.jmp_jge(),
    jne: Types.jmp_jne(),
    jlt: Types.jmp_jlt(),
    jle: Types.jmp_jle(),
    jsgt: Types.jmp_jsgt(),
    jsge: Types.jmp_jsge(),
    jslt: Types.jmp_jslt(),
    jsle: Types.jmp_jsle()
  }

  @doc """
  Assemble a list of IR nodes into a list of 8-byte BPF instruction binaries.

  Returns `{:ok, instructions, relocations}` where relocations is a list of
  `{byte_offset, map_index}` tuples for LD_IMM64 map references.
  """
  @spec assemble([VaistoBpf.IR.instruction()]) ::
          {:ok, [binary()], [{non_neg_integer(), non_neg_integer()}]}
          | {:error, Vaisto.Error.t()}
  def assemble(ir) do
    # Pass 1: Calculate label positions (ld_map_fd counts as 2 slots)
    labels = resolve_labels(ir)

    # Pass 2: Emit instructions, tracking relocations
    {instructions, relocations, _pos} =
      ir
      |> Enum.reject(&match?({:label, _}, &1))
      |> Enum.reduce({[], [], 0}, fn node, {insns, relocs, pos} ->
        case node do
          {:ld_map_fd, dst, map_index} ->
            {insn1, insn2} = Types.ld_map_fd(dst, map_index)
            byte_offset = pos * 8
            {[Types.encode(insn2), Types.encode(insn1) | insns],
             [{byte_offset, map_index} | relocs], pos + 2}

          _ ->
            bin = emit_instruction(node, pos, labels)
            {[bin | insns], relocs, pos + 1}
        end
      end)

    {:ok, Enum.reverse(instructions), Enum.reverse(relocations)}
  rescue
    e in RuntimeError -> {:error, Vaisto.Error.new(e.message)}
  end

  # ============================================================================
  # Pass 1: Label Resolution
  # ============================================================================

  defp resolve_labels(ir) do
    {labels, _pos} =
      Enum.reduce(ir, {%{}, 0}, fn
        {:label, name}, {labels, pos} ->
          {Map.put(labels, name, pos), pos}

        {:ld_map_fd, _dst, _map_index}, {labels, pos} ->
          # Wide instruction: occupies 2 slots
          {labels, pos + 2}

        _instruction, {labels, pos} ->
          {labels, pos + 1}
      end)

    labels
  end

  # ============================================================================
  # Pass 2: Instruction Emission
  # ============================================================================

  defp emit_instruction({:mov_imm, dst, imm}, _idx, _labels) do
    Types.encode(Types.mov64_imm(dst, imm))
  end

  defp emit_instruction({:mov_reg, dst, src}, _idx, _labels) do
    Types.encode(Types.mov64_reg(dst, src))
  end

  defp emit_instruction({:alu64_imm, op, dst, imm}, _idx, _labels) do
    Types.encode(Types.alu64_imm(resolve_alu_op(op), dst, imm))
  end

  defp emit_instruction({:alu64_reg, op, dst, src}, _idx, _labels) do
    Types.encode(Types.alu64_reg(resolve_alu_op(op), dst, src))
  end

  defp emit_instruction({:alu32_imm, op, dst, imm}, _idx, _labels) do
    Types.encode(Types.alu32_imm(resolve_alu_op(op), dst, imm))
  end

  defp emit_instruction({:alu32_reg, op, dst, src}, _idx, _labels) do
    Types.encode(Types.alu32_reg(resolve_alu_op(op), dst, src))
  end

  defp emit_instruction({:jmp_imm, op, dst, imm, label}, idx, labels) do
    target = Map.fetch!(labels, label)
    # BPF offset is relative to the instruction AFTER the jump
    offset = target - (idx + 1)
    Types.encode(Types.jmp_imm(resolve_jmp_op(op), dst, imm, offset))
  end

  defp emit_instruction({:jmp_reg, op, dst, src, label}, idx, labels) do
    target = Map.fetch!(labels, label)
    offset = target - (idx + 1)
    Types.encode(Types.jmp_reg(resolve_jmp_op(op), dst, src, offset))
  end

  defp emit_instruction({:ja, label}, idx, labels) do
    target = Map.fetch!(labels, label)
    offset = target - (idx + 1)
    Types.encode(Types.ja(offset))
  end

  defp emit_instruction({:call, helper_id}, _idx, _labels) do
    Types.encode(Types.call_helper(helper_id))
  end

  defp emit_instruction({:call_fn, label}, idx, labels) do
    target = Map.fetch!(labels, label)
    offset = target - (idx + 1)
    Types.encode(Types.call_bpf_fn(offset))
  end

  defp emit_instruction({:ldx_mem, size, dst, src, offset}, _idx, _labels) do
    Types.encode(Types.ldx_mem(size_to_mem_mode(size), dst, src, offset))
  end

  defp emit_instruction({:stx_mem, size, dst, src, offset}, _idx, _labels) do
    Types.encode(Types.stx_mem(size_to_mem_mode(size), dst, src, offset))
  end

  defp emit_instruction({:endian, :be, width, dst}, _idx, _labels) do
    Types.encode(Types.endian_be(dst, width))
  end

  defp emit_instruction({:endian, :le, width, dst}, _idx, _labels) do
    Types.encode(Types.endian_le(dst, width))
  end

  defp emit_instruction(:exit, _idx, _labels) do
    Types.encode(Types.exit_insn())
  end

  # ============================================================================
  # Opcode Resolution
  # ============================================================================

  defp resolve_alu_op(op), do: Map.fetch!(@alu_op_map, op)
  defp resolve_jmp_op(op), do: Map.fetch!(@jmp_op_map, op)

  defp size_to_mem_mode(:u8), do: Types.mem_b()
  defp size_to_mem_mode(:u16), do: Types.mem_h()
  defp size_to_mem_mode(:u32), do: Types.mem_w()
  defp size_to_mem_mode(:u64), do: Types.mem_dw()
end
