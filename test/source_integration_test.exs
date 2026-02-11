defmodule VaistoBpf.SourceIntegrationTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Types
  alias Vaisto.Error

  import Bitwise

  describe "compile_source/1 — end-to-end" do
    test "simple add function" do
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)

      assert Enum.all?(instructions, &(byte_size(&1) == 8))
      assert length(instructions) >= 3

      # Last instruction is exit
      last = Types.decode(List.last(instructions))
      assert last.opcode == (0x90 ||| 0x05)
    end

    test "conditional (if with comparison)" do
      source = "(defn max [a :u64 b :u64] :u64 (if (> a b) a b))"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) >= 5

      last = Types.decode(List.last(instructions))
      assert last.opcode == (0x90 ||| 0x05)
    end

    test "let binding" do
      source = "(defn double [x :u64] :u64 (let [y (+ x x)] y))"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) >= 3

      # Has ALU64 add
      has_add =
        Enum.any?(instructions, fn bin ->
          decoded = Types.decode(bin)
          decoded.opcode == 0x0F
        end)

      assert has_add
    end

    test "constant return with literal inference" do
      source = "(defn zero [] :u64 0)"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) >= 2
    end

    test "literal infers type from arithmetic context" do
      source = "(defn inc [x :u64] :u64 (+ x 1))"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)

      # Should use immediate form ALU64 (0x07 = ADD | ALU64 | IMM)
      has_alu64_imm =
        Enum.any?(instructions, fn bin ->
          decoded = Types.decode(bin)
          decoded.opcode == 0x07
        end)

      assert has_alu64_imm
    end

    test "32-bit operations use ALU32" do
      source = "(defn add32 [x :u32 y :u32] :u32 (+ x y))"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)

      has_alu32 =
        Enum.any?(instructions, fn bin ->
          decoded = Types.decode(bin)
          (decoded.opcode &&& 0x07) == 0x04 and (decoded.opcode &&& 0xF0) == 0x00
        end)

      assert has_alu32, "expected ALU32 instruction for u32 addition"
    end

    test "module with ns and multiple functions" do
      source = """
      (ns Math)
      (defn add [x :u64 y :u64] :u64 (+ x y))
      (defn sub [a :u64 b :u64] :u64 (- a b))
      """

      assert {:ok, instructions} = VaistoBpf.compile_source(source)

      exit_count =
        Enum.count(instructions, fn bin ->
          Types.decode(bin).opcode == (0x90 ||| 0x05)
        end)

      assert exit_count == 2
    end

    test "bitwise operations" do
      source = "(defn mask [x :u64 m :u64] :u64 (band x m))"
      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) >= 3
    end

    test "all 8 BPF integer types compile" do
      for type <- ~w(u8 u16 u32 u64 i8 i16 i32 i64) do
        source = "(defn f [x :#{type} y :#{type}] :#{type} (+ x y))"
        assert {:ok, _} = VaistoBpf.compile_source(source),
          "expected :#{type} to compile"
      end
    end

    test "nested arithmetic" do
      source = "(defn f [a :u64 b :u64 c :u64] :u64 (+ (+ a b) c))"
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "boolean comparisons in conditions" do
      source = """
      (defn clamp [x :u64 lo :u64 hi :u64] :u64
        (if (< x lo)
          lo
          (if (> x hi)
            hi
            x)))
      """
      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) >= 8
    end
  end

  describe "compile_source/1 — rejections" do
    test "rejects :int types" do
      source = "(defn f [x :int] :int (+ x 1))"
      assert {:error, %Error{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "not supported"
    end

    test "rejects :float types" do
      source = "(defn f [x :float] :float x)"
      assert {:error, %Error{}} = VaistoBpf.compile_source(source)
    end

    test "rejects mixed-width operations" do
      source = "(defn f [x :u64 y :u32] :u64 (+ x y))"
      assert {:error, %Error{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "same type"
    end

    test "rejects anonymous functions" do
      source = "(defn f [x :u64] :u64 (fn [y] y))"
      assert {:error, %Error{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "anonymous"
    end

    test "rejects return type mismatch" do
      source = "(defn f [x :u64 y :u64] :bool (+ x y))"
      assert {:error, %Error{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "return type mismatch"
    end
  end
end
