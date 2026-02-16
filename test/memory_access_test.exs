defmodule VaistoBpf.MemoryAccessTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Types

  import Bitwise

  describe "bpf/load_* builtins" do
    test "load_u64 compiles to LDX_MEM instruction" do
      source = """
      (defn read_val [ptr :u64] :u64 (bpf/load_u64 ptr 0))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # Should contain LDX_MEM DW instruction (opcode 0x79)
      assert has_opcode?(instructions, 0x79),
        "expected LDX_MEM DW (0x79) instruction"
    end

    test "load_u32 compiles to correct opcode" do
      source = """
      (defn read32 [ptr :u64] :u32 (bpf/load_u32 ptr 0))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # LDX | MEM | W = 0x61
      assert has_opcode?(instructions, 0x61),
        "expected LDX_MEM W (0x61) instruction"
    end

    test "load with non-zero offset" do
      source = """
      (defn read_field [ptr :u64] :u64 (bpf/load_u64 ptr 16))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      ldx = find_instruction(instructions, 0x79)
      assert ldx != nil
      assert ldx.offset == 16
    end

    test "no extern declaration needed" do
      # This should work without (extern bpf:load_u64 ...)
      source = """
      (defn f [ptr :u64] :u64 (bpf/load_u64 ptr 0))
      """

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "all load sizes compile" do
      sizes_and_opcodes = [
        {"u64", 0x79},
        {"u32", 0x61},
        {"u16", 0x69},
        {"u8",  0x71},
      ]

      for {size, opcode} <- sizes_and_opcodes do
        source = "(defn f [ptr :u64] :#{size} (bpf/load_#{size} ptr 0))"
        {:ok, instructions} = VaistoBpf.compile_source(source)
        assert has_opcode?(instructions, opcode),
          "load_#{size} should produce opcode 0x#{Integer.to_string(opcode, 16)}"
      end
    end
  end

  describe "bpf/store_* builtins" do
    test "store_u64 compiles to STX_MEM instruction" do
      source = """
      (defn write_val [ptr :u64 val :u64] :unit (bpf/store_u64 ptr 0 val))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # STX | MEM | DW = 0x7B
      assert has_opcode?(instructions, 0x7B),
        "expected STX_MEM DW (0x7B) instruction"
    end

    test "store_u32 compiles to correct opcode" do
      source = """
      (defn write32 [ptr :u64 val :u32] :unit (bpf/store_u32 ptr 4 val))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # STX | MEM | W = 0x63
      stx = find_instruction(instructions, 0x63)
      assert stx != nil
      assert stx.offset == 4
    end

    test "store with non-zero offset" do
      source = """
      (defn write_far [ptr :u64 val :u64] :unit (bpf/store_u64 ptr 24 val))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      stx = find_instruction(instructions, 0x7B)
      assert stx != nil
      assert stx.offset == 24
    end

    test "all store sizes compile" do
      sizes_and_opcodes = [
        {"u64", 0x7B},
        {"u32", 0x63},
        {"u16", 0x6B},
        {"u8",  0x73},
      ]

      for {size, opcode} <- sizes_and_opcodes do
        source = "(defn f [ptr :u64 val :#{size}] :unit (bpf/store_#{size} ptr 0 val))"
        {:ok, instructions} = VaistoBpf.compile_source(source)
        assert has_opcode?(instructions, opcode),
          "store_#{size} should produce opcode 0x#{Integer.to_string(opcode, 16)}"
      end
    end
  end

  describe "map lookup + load pattern" do
    test "map_lookup_elem → load_u64 compiles end-to-end" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn get_counter [key :u64] :u64
        (match (bpf/map_lookup_elem counters key)
          [(Some ptr) (bpf/load_u64 ptr 0)]
          [(None) 0]))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      # Should contain: CALL (helper), LDX_MEM (load), EXIT
      assert has_opcode?(instructions, 0x85), "expected CALL instruction"
      assert has_opcode?(instructions, 0x79), "expected LDX_MEM DW instruction"

      last = Types.decode(List.last(instructions))
      assert last.opcode == (0x90 ||| 0x05), "last instruction should be EXIT"
    end

    test "map_lookup_elem → store_u64 compiles end-to-end" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn set_counter [key :u64 val :u64] :u64
        (match (bpf/map_lookup_elem counters key)
          [(Some ptr) (do (bpf/store_u64 ptr 0 val) 1)]
          [(None) 0]))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)

      assert has_opcode?(instructions, 0x85), "expected CALL instruction"
      assert has_opcode?(instructions, 0x7B), "expected STX_MEM DW instruction"
    end
  end

  describe "error cases" do
    test "non-literal offset raises error" do
      source = """
      (defn bad [ptr :u64 off :u64] :u64 (bpf/load_u64 ptr off))
      """

      assert {:error, %Vaisto.Error{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "compile-time literal"
    end

    test "wrong argument count → type error" do
      source = """
      (defn bad [ptr :u64] :u64 (bpf/load_u64 ptr))
      """

      assert {:error, %Vaisto.Error{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "expects 2 arguments"
    end
  end

  describe "compiles to ELF" do
    test "load/store program produces valid ELF" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn get_counter [key :u64] :u64
        (match (bpf/map_lookup_elem counters key)
          [(Some ptr) (bpf/load_u64 ptr 0)]
          [(None) 0]))
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
      # ELF magic number
      assert <<0x7F, "ELF", _rest::binary>> = elf
    end
  end

  # ============================================================================
  # Test Helpers
  # ============================================================================

  defp has_opcode?(instructions, opcode) do
    Enum.any?(instructions, fn bin ->
      Types.decode(bin).opcode == opcode
    end)
  end

  defp find_instruction(instructions, opcode) do
    Enum.find_value(instructions, fn bin ->
      decoded = Types.decode(bin)
      if decoded.opcode == opcode, do: decoded, else: nil
    end)
  end
end
