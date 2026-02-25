defmodule VaistoBpf.PacketAccessTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Types

  describe "end-to-end XDP packet parsing" do
    test "basic packet bounds check compiles" do
      source = """
      (program :xdp)
      (defn xdp_check [ctx :XdpMd] :u32
        (let [data (u64 (. ctx :data))
              data_end (u64 (. ctx :data_end))]
          (if (> (+ data 14) data_end)
            1
            2)))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "packet parse with byte-swap and hex literal" do
      source = """
      (program :xdp)
      (defn xdp_filter [ctx :XdpMd] :u32
        (let [data (u64 (. ctx :data))
              data_end (u64 (. ctx :data_end))]
          (if (> (+ data 14) data_end)
            1
            (let [eth_type (bpf/be16 (bpf/load_u16 data 12))]
              (if (== eth_type 2048)
                2
                1)))))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "packet parse with hex literal 0x0800" do
      source = """
      (program :xdp)
      (defn xdp_filter [ctx :XdpMd] :u32
        (let [data (u64 (. ctx :data))
              data_end (u64 (. ctx :data_end))]
          (if (> (+ data 14) data_end)
            1
            (let [eth_type (bpf/be16 (bpf/load_u16 data 12))]
              (if (== eth_type 0x0800)
                2
                1)))))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "ELF output has xdp section" do
      source = """
      (program :xdp)
      (defn xdp_filter [ctx :XdpMd] :u32
        (let [data (u64 (. ctx :data))
              data_end (u64 (. ctx :data_end))]
          (if (> (+ data 14) data_end) 1 2)))
      """

      {:ok, elf_binary} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf_binary)
      # ELF magic number
      assert <<0x7F, "ELF", _rest::binary>> = elf_binary
    end

    test "instruction sequence contains expected operations" do
      source = """
      (program :xdp)
      (defn xdp_check [ctx :XdpMd] :u32
        (let [data (u64 (. ctx :data))
              data_end (u64 (. ctx :data_end))]
          (if (> (+ data 14) data_end)
            1
            2)))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # LDX_MEM W (0x61) for reading ctx->data (u32 field)
      assert has_opcode?(instructions, 0x61),
        "expected LDX_MEM W for ctx field access"

      # ALU64_IMM ADD (0x07) for pointer arithmetic (+14)
      assert has_opcode?(instructions, 0x07),
        "expected ALU64_IMM ADD for pointer arithmetic"
    end

    test "full packet parse includes endian instruction" do
      source = """
      (program :xdp)
      (defn xdp_filter [ctx :XdpMd] :u32
        (let [data (u64 (. ctx :data))
              data_end (u64 (. ctx :data_end))]
          (if (> (+ data 14) data_end)
            1
            (let [eth_type (bpf/be16 (bpf/load_u16 data 12))]
              (if (== eth_type 2048)
                2
                1)))))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # LDX_MEM H (0x69) for packet u16 load
      assert has_opcode?(instructions, 0x69),
        "expected LDX_MEM H for packet u16 load"

      # Endian BE (0xDC) with imm=16 for byte-swap
      endian_insn = find_instruction(instructions, 0xDC)
      assert endian_insn != nil, "expected endian BE instruction"
      assert endian_insn.imm == 16
    end
  end

  describe "hex literal parsing in BPF context" do
    test "hex literal as comparison value" do
      source = """
      (defn check_val [x :u32] :bool (== x 0xFF))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "hex literal in arithmetic" do
      source = """
      (defn add_hex [x :u32] :u32 (+ x 0x10))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end
  end

  # Helpers
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
