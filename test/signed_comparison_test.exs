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

  # Opcode constants for 64-bit jump instructions (JMP class = 0x05, src_reg = 0x08)
  @jlt64_reg 0xAD   # 0xA0 | 0x08 | 0x05
  @jsgt64_reg 0x6D  # 0x60 | 0x08 | 0x05
  @jslt64_reg 0xCD  # 0xC0 | 0x08 | 0x05
  @jne64_reg 0x5D   # 0x50 | 0x08 | 0x05

  # Opcode constants for 32-bit jump instructions (JMP32 class = 0x06, src_reg = 0x08)
  # Unsigned
  @jgt32_reg 0x2E   # 0x20 | 0x08 | 0x06
  @jge32_reg 0x3E   # 0x30 | 0x08 | 0x06
  @jlt32_reg 0xAE   # 0xA0 | 0x08 | 0x06
  @jle32_reg 0xBE   # 0xB0 | 0x08 | 0x06
  # Signed
  @jsgt32_reg 0x6E  # 0x60 | 0x08 | 0x06
  @jsge32_reg 0x7E  # 0x70 | 0x08 | 0x06
  @jslt32_reg 0xCE  # 0xC0 | 0x08 | 0x06
  @jsle32_reg 0xDE  # 0xD0 | 0x08 | 0x06
  # Sign-agnostic
  @jeq32_reg 0x1E   # 0x10 | 0x08 | 0x06

  describe "signed i32 comparisons emit signed JMP32 opcodes" do
    test "> with :i32 operands emits JSGT32" do
      ast = {:call, :>, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jsgt32_reg in opcodes(binary)
      refute @jgt32_reg in opcodes(binary)
    end

    test ">= with :i32 operands emits JSGE32" do
      ast = {:call, :>=, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jsge32_reg in opcodes(binary)
      refute @jge32_reg in opcodes(binary)
    end

    test "< with :i32 operands emits JSLT32" do
      ast = {:call, :<, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jslt32_reg in opcodes(binary)
      refute @jlt32_reg in opcodes(binary)
    end

    test "<= with :i32 operands emits JSLE32" do
      ast = {:call, :<=, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jsle32_reg in opcodes(binary)
      refute @jle32_reg in opcodes(binary)
    end
  end

  describe "signed i64 comparisons use signed JMP (64-bit) opcodes" do
    test "> with :i64 operands emits JSGT (64-bit)" do
      ast = {:call, :>, [{:var, :x, :i64}, {:var, :y, :i64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i64, :i64], :bool))
      assert @jsgt64_reg in opcodes(binary)
    end

    test "< with :i64 operands emits JSLT (64-bit)" do
      ast = {:call, :<, [{:var, :x, :i64}, {:var, :y, :i64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i64, :i64], :bool))
      assert @jslt64_reg in opcodes(binary)
    end
  end

  describe "unsigned comparisons emit correct width" do
    test "> with :u32 operands emits JGT32 (unsigned, 32-bit)" do
      ast = {:call, :>, [{:var, :x, :u32}, {:var, :y, :u32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:u32, :u32], :bool))
      assert @jgt32_reg in opcodes(binary)
      refute @jsgt32_reg in opcodes(binary)
    end

    test "< with :u64 operands emits JLT (unsigned, 64-bit)" do
      ast = {:call, :<, [{:var, :x, :u64}, {:var, :y, :u64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:u64, :u64], :bool))
      assert @jlt64_reg in opcodes(binary)
      refute @jslt64_reg in opcodes(binary)
    end
  end

  describe "== and != are unaffected by signedness" do
    test "== with :i32 operands emits JEQ32 (sign-agnostic, 32-bit)" do
      ast = {:call, :==, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i32, :i32], :bool))
      assert @jeq32_reg in opcodes(binary)
    end

    test "!= with :i64 operands emits JNE (sign-agnostic, 64-bit)" do
      ast = {:call, :!=, [{:var, :x, :i64}, {:var, :y, :i64}], :bool}
      binary = compile_to_binary(wrap_in_fn(:cmp, [:x, :y], ast, [:i64, :i64], :bool))
      assert @jne64_reg in opcodes(binary)
    end
  end

  describe "signed comparison in if produces correct branch" do
    test "if (x > y) with :i32 uses signed JMP32 in IR" do
      cond_ast = {:call, :>, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      if_ast = {:if, cond_ast, {:lit, :int, 1}, {:lit, :int, 0}, :i32}
      fn_ast = wrap_in_fn(:check, [:x, :y], if_ast, [:i32, :i32], :i32)

      {:ok, ir} = Emitter.emit(fn_ast)
      # The comparison inside if should produce a jsgt JMP32 jump
      assert Enum.any?(ir, fn
        {:jmp32_reg, :jsgt, _, _, _} -> true
        _ -> false
      end)
    end
  end
end
