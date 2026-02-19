defmodule VaistoBpf.TypeCastTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Types

  describe "type cast type checking" do
    test "widening u32 to u64" do
      source = """
      (defn widen [x :u32] :u64 (u64 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "narrowing u64 to u32" do
      source = """
      (defn narrow [x :u64] :u32 (u32 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "identity cast u32 to u32" do
      source = """
      (defn identity [x :u32] :u32 (u32 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "cast from u16 to u64" do
      source = """
      (defn widen16 [x :u16] :u64 (u64 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "cast u64 to u8 (narrow)" do
      source = """
      (defn to_byte [x :u64] :u8 (u8 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "cast rejects non-integer source type" do
      source = """
      (defn bad_cast [x :bool] :u64 (u64 x))
      """

      assert {:error, err} = VaistoBpf.compile_source(source)
      assert err.message =~ "type cast requires an integer type"
    end

    test "cast of field access expression" do
      source = """
      (defn cast_field [ctx :XdpMd] :u64 (u64 (. ctx :data)))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end
  end

  describe "type cast emitter" do
    test "widening produces no AND mask instruction" do
      source = """
      (defn widen [x :u32] :u64 (u64 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # AND opcode for ALU64: 0x57 (imm) or 0x5f (reg)
      refute has_opcode?(instructions, 0x57),
        "widening should not produce ALU64_AND instruction"
    end

    test "narrowing produces AND mask instruction" do
      source = """
      (defn narrow [x :u64] :u32 (u32 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # ALU64_IMM AND = 0x57
      and_insn = find_instruction(instructions, 0x57)
      assert and_insn != nil, "narrowing should produce ALU64_AND instruction"
      # Mask for u32: 0xFFFFFFFF, stored as signed 32-bit = -1
      assert and_insn.imm == -1
    end

    test "narrowing to u16 produces correct mask" do
      source = """
      (defn narrow16 [x :u64] :u16 (u16 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      and_insn = find_instruction(instructions, 0x57)
      assert and_insn != nil
      assert and_insn.imm == 0xFFFF
    end

    test "narrowing to u8 produces correct mask" do
      source = """
      (defn narrow8 [x :u64] :u8 (u8 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      and_insn = find_instruction(instructions, 0x57)
      assert and_insn != nil
      assert and_insn.imm == 0xFF
    end
  end

  # Helper functions
  defp has_opcode?(instructions, target_opcode) do
    Enum.any?(instructions, fn bin ->
      <<opcode::8, _rest::binary>> = bin
      opcode == target_opcode
    end)
  end

  defp find_instruction(instructions, target_opcode) do
    Enum.find_value(instructions, fn bin ->
      decoded = Types.decode(bin)
      if decoded.opcode == target_opcode, do: decoded
    end)
  end
end
