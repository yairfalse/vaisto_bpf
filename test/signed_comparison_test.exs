defmodule VaistoBpf.SignedComparisonTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Emitter
  alias VaistoBpf.Assembler

  # Helper: wrap an expression in a defn so the emitter is happy
  defp wrap_in_fn(name, params, body, arg_types, ret_type) do
    {:defn, name, params, body, {:fn, arg_types, ret_type}}
  end

  # Helper: compile AST to binary and return the raw bytes
  defp compile_to_binary(ast) do
    {:ok, ir} = Emitter.emit(ast)
    {:ok, instructions, _relocs} = Assembler.assemble(ir)
    IO.iodata_to_binary(instructions)
  end

  # Helper: extract all opcodes from binary
  defp opcodes(binary) do
    for <<opcode::8, _rest::binary-size(7) <- binary>>, do: opcode
  end

  # Opcode constants for jump instructions (JMP class = 0x05, src_reg = 0x08)
  # Unsigned
  @jgt_reg 0x2D   # 0x20 | 0x08 | 0x05
  @jge_reg 0x3D   # 0x30 | 0x08 | 0x05
  @jlt_reg 0xAD   # 0xA0 | 0x08 | 0x05
  @jle_reg 0xBD   # 0xB0 | 0x08 | 0x05
  # Signed
  @jsgt_reg 0x6D  # 0x60 | 0x08 | 0x05
  @jsge_reg 0x7D  # 0x70 | 0x08 | 0x05
  @jslt_reg 0xCD  # 0xC0 | 0x08 | 0x05
  @jsle_reg 0xDD  # 0xD0 | 0x08 | 0x05
  # Sign-agnostic
  @jeq_reg 0x1D   # 0x10 | 0x08 | 0x05
  @jne_reg 0x5D   # 0x50 | 0x08 | 0x05

  describe "signed i32 comparisons emit signed jump opcodes" do
    test "> with :i32 operands emits JSGT" do
      ast = {:call, :>, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jsgt_reg in opcodes(binary)
      refute @jgt_reg in opcodes(binary)
    end

    test ">= with :i32 operands emits JSGE" do
      ast = {:call, :>=, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jsge_reg in opcodes(binary)
      refute @jge_reg in opcodes(binary)
    end

    test "< with :i32 operands emits JSLT" do
      ast = {:call, :<, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jslt_reg in opcodes(binary)
      refute @jlt_reg in opcodes(binary)
    end

    test "<= with :i32 operands emits JSLE" do
      ast = {:call, :<=, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jsle_reg in opcodes(binary)
      refute @jle_reg in opcodes(binary)
    end
  end

  describe "signed i64 comparisons also use signed opcodes" do
    test "> with :i64 operands emits JSGT" do
      ast = {:call, :>, [{:var, :x, :i64}, {:var, :y, :i64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i64, :i64], :bool))
      assert @jsgt_reg in opcodes(binary)
    end

    test "< with :i64 operands emits JSLT" do
      ast = {:call, :<, [{:var, :x, :i64}, {:var, :y, :i64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i64, :i64], :bool))
      assert @jslt_reg in opcodes(binary)
    end
  end

  describe "unsigned comparisons still emit unsigned opcodes (no regression)" do
    test "> with :u32 operands emits JGT (unsigned)" do
      ast = {:call, :>, [{:var, :x, :u32}, {:var, :y, :u32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:u32, :u32], :bool))
      assert @jgt_reg in opcodes(binary)
      refute @jsgt_reg in opcodes(binary)
    end

    test "< with :u64 operands emits JLT (unsigned)" do
      ast = {:call, :<, [{:var, :x, :u64}, {:var, :y, :u64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:u64, :u64], :bool))
      assert @jlt_reg in opcodes(binary)
      refute @jslt_reg in opcodes(binary)
    end
  end

  describe "== and != are unaffected by signedness" do
    test "== with :i32 operands emits JEQ (sign-agnostic)" do
      ast = {:call, :==, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jeq_reg in opcodes(binary)
    end

    test "!= with :i64 operands emits JNE (sign-agnostic)" do
      ast = {:call, :!=, [{:var, :x, :i64}, {:var, :y, :i64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i64, :i64], :bool))
      assert @jne_reg in opcodes(binary)
    end
  end

  describe "signed comparison in if produces correct branch" do
    test "if (x > y) with :i32 uses signed jump in IR" do
      cond_ast = {:call, :>, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      if_ast = {:if, cond_ast, {:lit, :int, 1}, {:lit, :int, 0}, :i32}
      fn_ast = wrap_in_fn(:check, [:x, :y], if_ast, [:i32, :i32], :i32)

      {:ok, ir} = Emitter.emit(fn_ast)
      # The comparison inside if should produce a jsgt jump
      assert Enum.any?(ir, fn
        {:jmp_reg, :jsgt, _, _, _} -> true
        _ -> false
      end)
    end
  end
end
