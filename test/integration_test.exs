defmodule VaistoBpf.IntegrationTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Types

  import Bitwise

  describe "end-to-end: typed AST → BPF bytecode" do
    test "simple add function compiles to valid BPF instructions" do
      # Typed AST for: (defn add [x :u64 y :u64] :u64 (+ x y))
      typed_ast =
        {:defn, :add, [:x, :y],
         {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64},
         {:fn, [:u64, :u64], :u64}}

      assert {:ok, instructions} = VaistoBpf.compile(typed_ast)

      # All instructions are 8 bytes
      assert Enum.all?(instructions, &(byte_size(&1) == 8))

      # Should have at least: alu instruction + mov to r0 + exit
      assert length(instructions) >= 3

      # Last instruction must be exit (0x95 = EXIT | JMP)
      last = Types.decode(List.last(instructions))
      assert last.opcode == (0x90 ||| 0x05)
    end

    test "constant function" do
      # (defn zero [] :u64 0)
      typed_ast =
        {:defn, :zero, [],
         {:lit, :int, 0},
         {:fn, [], :u64}}

      assert {:ok, instructions} = VaistoBpf.compile(typed_ast)

      # Should be: mov_imm rN, 0; mov_reg r0, rN; exit
      assert length(instructions) >= 2

      # Verify exit
      last = Types.decode(List.last(instructions))
      assert last.opcode == (0x90 ||| 0x05)
    end

    test "if expression compiles" do
      # (defn choose [cond :bool] :u64 (if cond 1 0))
      typed_ast =
        {:defn, :choose, [:cond],
         {:if, {:var, :cond, :bool},
          {:lit, :int, 1}, {:lit, :int, 0}, :u64},
         {:fn, [:bool], :u64}}

      assert {:ok, instructions} = VaistoBpf.compile(typed_ast)

      # Should have conditional jump, both branches, and exit
      assert length(instructions) >= 5

      # Verify exit at end
      last = Types.decode(List.last(instructions))
      assert last.opcode == (0x90 ||| 0x05)
    end

    test "let binding compiles" do
      # (defn double [x :u64] :u64 (let [y (+ x x)] y))
      typed_ast =
        {:defn, :double, [:x],
         {:let, [{{:var, :y, :u64}, {:call, :+, [{:var, :x, :u64}, {:var, :x, :u64}], :u64}}],
          {:var, :y, :u64}, :u64},
         {:fn, [:u64], :u64}}

      assert {:ok, instructions} = VaistoBpf.compile(typed_ast)
      assert length(instructions) >= 3

      # Has an ALU64 add instruction
      has_add =
        Enum.any?(instructions, fn bin ->
          decoded = Types.decode(bin)
          # ALU64 ADD REG = 0x00 | 0x08 | 0x07 = 0x0F
          decoded.opcode == 0x0F
        end)

      assert has_add
    end

    test "module with multiple functions" do
      typed_ast =
        {:module, [
          {:ns, :TestMod},
          {:defn, :inc, [:x],
           {:call, :+, [{:var, :x, :u64}, {:lit, :int, 1}], :u64},
           {:fn, [:u64], :u64}},
          {:defn, :dec, [:x],
           {:call, :-, [{:var, :x, :u32}, {:lit, :int, 1}], :u32},
           {:fn, [:u32], :u32}}
        ]}

      assert {:ok, instructions} = VaistoBpf.compile(typed_ast)

      # Two functions → two exit instructions
      exit_count =
        Enum.count(instructions, fn bin ->
          Types.decode(bin).opcode == (0x90 ||| 0x05)
        end)

      assert exit_count == 2
    end

    test "32-bit vs 64-bit ALU" do
      # u64 should use ALU64 class (0x07), u32 should use ALU class (0x04)
      typed_ast_64 =
        {:defn, :add64, [:x, :y],
         {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64},
         {:fn, [:u64, :u64], :u64}}

      typed_ast_32 =
        {:defn, :add32, [:x, :y],
         {:call, :+, [{:var, :x, :u32}, {:var, :y, :u32}], :u32},
         {:fn, [:u32, :u32], :u32}}

      {:ok, insns_64} = VaistoBpf.compile(typed_ast_64)
      {:ok, insns_32} = VaistoBpf.compile(typed_ast_32)

      # 64-bit should use ALU64 (class 0x07)
      has_alu64 =
        Enum.any?(insns_64, fn bin ->
          decoded = Types.decode(bin)
          (decoded.opcode &&& 0x07) == 0x07 and (decoded.opcode &&& 0xF0) == 0x00
        end)

      # 32-bit should use ALU (class 0x04)
      has_alu32 =
        Enum.any?(insns_32, fn bin ->
          decoded = Types.decode(bin)
          (decoded.opcode &&& 0x07) == 0x04 and (decoded.opcode &&& 0xF0) == 0x00
        end)

      assert has_alu64, "expected ALU64 instruction for u64 addition"
      assert has_alu32, "expected ALU32 instruction for u32 addition"
    end
  end

  describe "validation rejects invalid BPF" do
    test "rejects float in pipeline" do
      typed_ast = {:var, :x, :float}
      assert {:error, %Vaisto.Error{}} = VaistoBpf.compile(typed_ast)
    end

    test "rejects recursion in pipeline" do
      typed_ast =
        {:defn, :loop, [:x],
         {:call, :loop, [{:var, :x, :u64}], :u64},
         {:fn, [:u64], :u64}}

      assert {:error, %Vaisto.Error{message: msg}} = VaistoBpf.compile(typed_ast)
      assert msg =~ "recursion"
    end

    test "rejects anonymous functions in pipeline" do
      typed_ast = {:fn, [:x], {:var, :x, :u64}, {:fn, [:u64], :u64}}
      assert {:error, %Vaisto.Error{message: msg}} = VaistoBpf.compile(typed_ast)
      assert msg =~ "anonymous"
    end
  end

  describe "validate/1 standalone" do
    test "validates without compiling" do
      typed_ast =
        {:defn, :ok_fn, [:x],
         {:var, :x, :u64},
         {:fn, [:u64], :u64}}

      assert {:ok, ^typed_ast} = VaistoBpf.validate(typed_ast)
    end

    test "returns error for invalid" do
      assert {:error, %Vaisto.Error{}} = VaistoBpf.validate({:lit, :float, 3.14})
    end
  end
end
