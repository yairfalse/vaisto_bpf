defmodule VaistoBpf.SignedArithmeticTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Emitter
  alias VaistoBpf.Assembler
  alias VaistoBpf.Types
  import Bitwise

  # Helper: wrap an expression in a defn
  defp wrap_in_fn(name, params, body, arg_types, ret_type) do
    {:defn, name, params, body, {:fn, arg_types, ret_type}}
  end

  # Helper: compile AST to IR
  defp compile_to_ir(ast) do
    {:ok, ir} = Emitter.emit(ast)
    ir
  end

  # Helper: compile AST to binary and decode all instructions
  defp compile_and_decode(ast) do
    {:ok, ir} = Emitter.emit(ast)
    {:ok, instructions, _relocs} = Assembler.assemble(ir)
    binary = IO.iodata_to_binary(instructions)
    for <<chunk::binary-size(8) <- binary>>, do: Types.decode(chunk)
  end

  # ALU opcode constants
  @bpf_div 0x30
  @bpf_mod 0x90
  @bpf_rsh 0x70
  @bpf_arsh 0xC0

  # Instruction classes
  @bpf_alu64 0x07
  @bpf_alu32 0x04
  @bpf_k 0x00
  @bpf_x 0x08

  # Derived opcodes
  @div64_reg @bpf_div ||| @bpf_x ||| @bpf_alu64
  @div32_reg @bpf_div ||| @bpf_x ||| @bpf_alu32
  @mod64_reg @bpf_mod ||| @bpf_x ||| @bpf_alu64
  @mod32_reg @bpf_mod ||| @bpf_x ||| @bpf_alu32
  @rsh64_reg @bpf_rsh ||| @bpf_x ||| @bpf_alu64
  @arsh64_reg @bpf_arsh ||| @bpf_x ||| @bpf_alu64
  @div64_imm @bpf_div ||| @bpf_k ||| @bpf_alu64
  @mod64_imm @bpf_mod ||| @bpf_k ||| @bpf_alu64

  # SUB opcodes for negation tests
  @bpf_sub 0x10
  @sub64_reg @bpf_sub ||| @bpf_x ||| @bpf_alu64
  @sub32_reg @bpf_sub ||| @bpf_x ||| @bpf_alu32

  # ADD opcodes for loop tests
  @bpf_add 0x00
  @add64_imm @bpf_add ||| @bpf_k ||| @bpf_alu64
  @add32_imm @bpf_add ||| @bpf_k ||| @bpf_alu32

  describe "signed division emits SDIV (offset=1)" do
    test ":i32 div emits DIV opcode with offset=1" do
      ast = {:call, :div, [{:var, :x, :i32}, {:var, :y, :i32}], :i32}
      decoded = compile_and_decode(wrap_in_fn(:sdiv_test, [:x, :y], ast, [:i32, :i32], :i32))

      div_insns = Enum.filter(decoded, fn insn -> insn.opcode == @div32_reg end)
      assert length(div_insns) == 1
      assert hd(div_insns).offset == 1
    end

    test ":i64 div emits DIV64 opcode with offset=1" do
      ast = {:call, :div, [{:var, :x, :i64}, {:var, :y, :i64}], :i64}
      decoded = compile_and_decode(wrap_in_fn(:sdiv_test, [:x, :y], ast, [:i64, :i64], :i64))

      div_insns = Enum.filter(decoded, fn insn -> insn.opcode == @div64_reg end)
      assert length(div_insns) == 1
      assert hd(div_insns).offset == 1
    end

    test ":u32 div emits DIV opcode with offset=0 (unsigned)" do
      ast = {:call, :div, [{:var, :x, :u32}, {:var, :y, :u32}], :u32}
      decoded = compile_and_decode(wrap_in_fn(:udiv_test, [:x, :y], ast, [:u32, :u32], :u32))

      div_insns = Enum.filter(decoded, fn insn -> insn.opcode == @div32_reg end)
      assert length(div_insns) == 1
      assert hd(div_insns).offset == 0
    end

    test ":i64 div with immediate emits offset=1" do
      ast = {:call, :div, [{:var, :x, :i64}, {:lit, :int, 2}], :i64}
      decoded = compile_and_decode(wrap_in_fn(:sdiv_imm, [:x], ast, [:i64], :i64))

      div_insns = Enum.filter(decoded, fn insn -> insn.opcode == @div64_imm end)
      assert length(div_insns) == 1
      assert hd(div_insns).offset == 1
    end
  end

  describe "signed modulo emits SMOD (offset=1)" do
    test ":i32 rem emits MOD opcode with offset=1" do
      ast = {:call, :rem, [{:var, :x, :i32}, {:var, :y, :i32}], :i32}
      decoded = compile_and_decode(wrap_in_fn(:smod_test, [:x, :y], ast, [:i32, :i32], :i32))

      mod_insns = Enum.filter(decoded, fn insn -> insn.opcode == @mod32_reg end)
      assert length(mod_insns) == 1
      assert hd(mod_insns).offset == 1
    end

    test ":u64 rem emits MOD opcode with offset=0 (unsigned)" do
      ast = {:call, :rem, [{:var, :x, :u64}, {:var, :y, :u64}], :u64}
      decoded = compile_and_decode(wrap_in_fn(:umod_test, [:x, :y], ast, [:u64, :u64], :u64))

      mod_insns = Enum.filter(decoded, fn insn -> insn.opcode == @mod64_reg end)
      assert length(mod_insns) == 1
      assert hd(mod_insns).offset == 0
    end

    test ":i64 rem with immediate emits offset=1" do
      ast = {:call, :rem, [{:var, :x, :i64}, {:lit, :int, 3}], :i64}
      decoded = compile_and_decode(wrap_in_fn(:smod_imm, [:x], ast, [:i64], :i64))

      mod_insns = Enum.filter(decoded, fn insn -> insn.opcode == @mod64_imm end)
      assert length(mod_insns) == 1
      assert hd(mod_insns).offset == 1
    end
  end

  describe "signed right shift emits ARSH" do
    test ":i32 bsr emits ARSH opcode" do
      ast = {:call, :bsr, [{:var, :x, :i32}, {:var, :y, :i32}], :i32}
      decoded = compile_and_decode(wrap_in_fn(:arsh_test, [:x, :y], ast, [:i32, :i32], :i32))

      opcodes = Enum.map(decoded, & &1.opcode)
      # ARSH uses the arsh opcode, not rsh
      assert (@bpf_arsh ||| @bpf_x ||| @bpf_alu32) in opcodes
      refute (@bpf_rsh ||| @bpf_x ||| @bpf_alu32) in opcodes
    end

    test ":u64 bsr emits RSH opcode (unsigned)" do
      ast = {:call, :bsr, [{:var, :x, :u64}, {:var, :y, :u64}], :u64}
      decoded = compile_and_decode(wrap_in_fn(:rsh_test, [:x, :y], ast, [:u64, :u64], :u64))

      opcodes = Enum.map(decoded, & &1.opcode)
      assert @rsh64_reg in opcodes
      refute @arsh64_reg in opcodes
    end
  end

  describe "negation respects operand width" do
    test "negation of :u32 emits alu32_reg sub" do
      ast = {:call, :-, [{:var, :x, :u32}], :u32}
      ir = compile_to_ir(wrap_in_fn(:neg32, [:x], ast, [:u32], :u32))

      assert Enum.any?(ir, &match?({:alu32_reg, :sub, _, _}, &1))
      refute Enum.any?(ir, &match?({:alu64_reg, :sub, _, _}, &1))
    end

    test "negation of :u64 emits alu64_reg sub" do
      ast = {:call, :-, [{:var, :x, :u64}], :u64}
      ir = compile_to_ir(wrap_in_fn(:neg64, [:x], ast, [:u64], :u64))

      assert Enum.any?(ir, &match?({:alu64_reg, :sub, _, _}, &1))
    end

    test "negation width encodes correctly in binary" do
      ast = {:call, :-, [{:var, :x, :u32}], :u32}
      decoded = compile_and_decode(wrap_in_fn(:neg32_bin, [:x], ast, [:u32], :u32))

      opcodes = Enum.map(decoded, & &1.opcode)
      assert @sub32_reg in opcodes
      refute @sub64_reg in opcodes
    end
  end

  describe "loop increment respects iterator width" do
    test "for_range with :u32 iterator emits alu32_imm add" do
      body = {:var, :i, :u32}
      ast = {:for_range, :i, {:lit, :int, 0}, {:lit, :int, 10}, body, :u32}
      ir = compile_to_ir(wrap_in_fn(:loop32, [], ast, [], :unit))

      assert Enum.any?(ir, &match?({:alu32_imm, :add, _, 1}, &1))
      refute Enum.any?(ir, &match?({:alu64_imm, :add, _, 1}, &1))
    end

    test "for_range with :u64 iterator emits alu64_imm add" do
      body = {:var, :i, :u64}
      ast = {:for_range, :i, {:lit, :int, 0}, {:lit, :int, 10}, body, :u64}
      ir = compile_to_ir(wrap_in_fn(:loop64, [], ast, [], :unit))

      assert Enum.any?(ir, &match?({:alu64_imm, :add, _, 1}, &1))
    end

    test "loop increment width encodes correctly in binary" do
      body = {:var, :i, :u32}
      ast = {:for_range, :i, {:lit, :int, 0}, {:lit, :int, 5}, body, :u32}
      decoded = compile_and_decode(wrap_in_fn(:loop32_bin, [], ast, [], :unit))

      add_insns = Enum.filter(decoded, fn insn ->
        insn.opcode == @add32_imm and insn.imm == 1
      end)
      assert length(add_insns) == 1

      # No 64-bit add with imm=1
      add64_insns = Enum.filter(decoded, fn insn ->
        insn.opcode == @add64_imm and insn.imm == 1
      end)
      assert add64_insns == []
    end
  end

  describe "== and != unaffected by signed alu changes" do
    test "equality with signed types doesn't produce signed ALU ops" do
      ast = {:call, :==, [{:var, :x, :i32}, {:var, :y, :i32}], :bool}
      ir = compile_to_ir(wrap_in_fn(:eq_test, [:x, :y], ast, [:i32, :i32], :bool))

      # Should use jeq, not any signed ALU variant
      assert Enum.any?(ir, &match?({:jmp_reg, :jeq, _, _, _}, &1))
    end
  end
end
