defmodule VaistoBpf.ByteSwapTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Types

  describe "byte-swap type checking" do
    test "bpf/be16 accepts u16 and returns u16" do
      source = """
      (defn swap16 [x :u16] :u16 (bpf/be16 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "bpf/be32 accepts u32 and returns u32" do
      source = """
      (defn swap32 [x :u32] :u32 (bpf/be32 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "bpf/be64 accepts u64 and returns u64" do
      source = """
      (defn swap64 [x :u64] :u64 (bpf/be64 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "bpf/le16 accepts u16 and returns u16" do
      source = """
      (defn swap_le16 [x :u16] :u16 (bpf/le16 x))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "bpf/be16 rejects u64 argument (type mismatch)" do
      source = """
      (defn bad_swap [x :u64] :u64 (bpf/be16 x))
      """

      assert {:error, _} = VaistoBpf.compile_source(source)
    end

    test "bpf/be32 rejects u16 argument" do
      source = """
      (defn bad_swap [x :u16] :u16 (bpf/be32 x))
      """

      assert {:error, _} = VaistoBpf.compile_source(source)
    end
  end

  describe "byte-swap instruction encoding" do
    test "be16 produces correct BPF endian opcode" do
      source = """
      (defn swap16 [x :u16] :u16 (bpf/be16 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # BPF_END | BPF_TO_BE | BPF_ALU = 0xD0 | 0x08 | 0x04 = 0xDC
      endian_insn = find_instruction(instructions, 0xDC)
      assert endian_insn != nil, "expected endian BE instruction (0xDC)"
      assert endian_insn.imm == 16
    end

    test "be32 encodes with imm=32" do
      source = """
      (defn swap32 [x :u32] :u32 (bpf/be32 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      endian_insn = find_instruction(instructions, 0xDC)
      assert endian_insn != nil
      assert endian_insn.imm == 32
    end

    test "be64 encodes with imm=64" do
      source = """
      (defn swap64 [x :u64] :u64 (bpf/be64 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      endian_insn = find_instruction(instructions, 0xDC)
      assert endian_insn != nil
      assert endian_insn.imm == 64
    end

    test "le16 produces LE endian opcode" do
      source = """
      (defn swap_le [x :u16] :u16 (bpf/le16 x))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # BPF_END | BPF_TO_LE | BPF_ALU = 0xD0 | 0x00 | 0x04 = 0xD4
      endian_insn = find_instruction(instructions, 0xD4)
      assert endian_insn != nil, "expected endian LE instruction (0xD4)"
      assert endian_insn.imm == 16
    end
  end

  describe "byte-swap combined with memory access" do
    test "bpf/be16 of loaded u16 value" do
      source = """
      (defn swap_loaded [ptr :u64] :u16
        (bpf/be16 (bpf/load_u16 ptr 0)))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end
  end

  # Helpers
  defp find_instruction(instructions, target_opcode) do
    Enum.find_value(instructions, fn bin ->
      decoded = Types.decode(bin)
      if decoded.opcode == target_opcode, do: decoded
    end)
  end
end
