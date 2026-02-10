defmodule VaistoBpf.AssemblerTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Assembler
  alias VaistoBpf.Types

  import Bitwise

  describe "instruction encoding" do
    test "mov64_imm encodes correctly" do
      ir = [{:mov_imm, 1, 42}]
      {:ok, [binary]} = Assembler.assemble(ir)

      assert byte_size(binary) == 8
      decoded = Types.decode(binary)
      assert decoded.dst == 1
      assert decoded.imm == 42
      # opcode should be MOV | K | ALU64
      assert decoded.opcode == (0xB0 ||| 0x00 ||| 0x07)
    end

    test "mov64_reg encodes correctly" do
      ir = [{:mov_reg, 2, 3}]
      {:ok, [binary]} = Assembler.assemble(ir)

      decoded = Types.decode(binary)
      assert decoded.dst == 2
      assert decoded.src == 3
      assert decoded.opcode == (0xB0 ||| 0x08 ||| 0x07)
    end

    test "alu64_imm add encodes correctly" do
      ir = [{:alu64_imm, :add, 1, 10}]
      {:ok, [binary]} = Assembler.assemble(ir)

      decoded = Types.decode(binary)
      assert decoded.dst == 1
      assert decoded.imm == 10
      # ADD | K | ALU64 = 0x00 | 0x00 | 0x07
      assert decoded.opcode == 0x07
    end

    test "alu64_reg sub encodes correctly" do
      ir = [{:alu64_reg, :sub, 1, 2}]
      {:ok, [binary]} = Assembler.assemble(ir)

      decoded = Types.decode(binary)
      assert decoded.dst == 1
      assert decoded.src == 2
      # SUB | X | ALU64 = 0x10 | 0x08 | 0x07
      assert decoded.opcode == (0x10 ||| 0x08 ||| 0x07)
    end

    test "alu32_imm encodes correctly" do
      ir = [{:alu32_imm, :mul, 3, 5}]
      {:ok, [binary]} = Assembler.assemble(ir)

      decoded = Types.decode(binary)
      assert decoded.dst == 3
      assert decoded.imm == 5
      # MUL | K | ALU = 0x20 | 0x00 | 0x04
      assert decoded.opcode == (0x20 ||| 0x04)
    end

    test "exit encodes correctly" do
      ir = [:exit]
      {:ok, [binary]} = Assembler.assemble(ir)

      decoded = Types.decode(binary)
      # EXIT | JMP = 0x90 | 0x05
      assert decoded.opcode == (0x90 ||| 0x05)
      assert decoded.dst == 0
      assert decoded.src == 0
      assert decoded.offset == 0
      assert decoded.imm == 0
    end

    test "call helper encodes correctly" do
      ir = [{:call, 14}]
      {:ok, [binary]} = Assembler.assemble(ir)

      decoded = Types.decode(binary)
      # CALL | JMP = 0x80 | 0x05
      assert decoded.opcode == (0x80 ||| 0x05)
      assert decoded.imm == 14
    end
  end

  describe "all instructions are 8 bytes" do
    test "every instruction is exactly 8 bytes" do
      ir = [
        {:mov_imm, 1, 0},
        {:mov_reg, 2, 1},
        {:alu64_imm, :add, 1, 5},
        {:alu64_reg, :sub, 2, 1},
        {:alu32_imm, :mul, 3, 2},
        {:alu32_reg, :div, 4, 3},
        :exit
      ]

      {:ok, instructions} = Assembler.assemble(ir)
      assert length(instructions) == 7
      assert Enum.all?(instructions, &(byte_size(&1) == 8))
    end
  end

  describe "label resolution" do
    test "forward jump resolves correctly" do
      ir = [
        {:jmp_imm, :jeq, 1, 0, :skip},
        {:mov_imm, 1, 42},
        {:label, :skip},
        {:mov_imm, 1, 0}
      ]

      {:ok, instructions} = Assembler.assemble(ir)
      # 3 instructions (labels are stripped)
      assert length(instructions) == 3

      # First instruction: jump. Target is instruction index 2 (the mov_imm 0).
      # Jump is at index 0, so offset = 2 - (0+1) = 1
      decoded = Types.decode(Enum.at(instructions, 0))
      assert decoded.offset == 1
    end

    test "backward jump resolves correctly" do
      ir = [
        {:label, :loop},
        {:mov_imm, 1, 1},
        {:ja, :loop}
      ]

      {:ok, instructions} = Assembler.assemble(ir)
      assert length(instructions) == 2

      # ja at index 1, target at index 0: offset = 0 - (1+1) = -2
      decoded = Types.decode(Enum.at(instructions, 1))
      assert decoded.offset == -2
    end

    test "conditional jump over one instruction" do
      ir = [
        {:jmp_reg, :jgt, 1, 2, :greater},
        {:mov_imm, 0, 0},
        {:ja, :end},
        {:label, :greater},
        {:mov_imm, 0, 1},
        {:label, :end},
        :exit
      ]

      {:ok, instructions} = Assembler.assemble(ir)
      # Labels are stripped: 5 instructions
      assert length(instructions) == 5

      # jmp_reg at idx 0, :greater at idx 3 (after stripping labels)
      # Actually: :greater label is at position 3 in original,
      # but instructions without labels: idx 0=jmp_reg, 1=mov_imm, 2=ja, 3=mov_imm, 4=exit
      # :greater label points to instruction position 3
      decoded_jmp = Types.decode(Enum.at(instructions, 0))
      assert decoded_jmp.offset == 2  # 3 - (0+1) = 2

      # ja at idx 2, :end is at position 4
      decoded_ja = Types.decode(Enum.at(instructions, 2))
      assert decoded_ja.offset == 1  # 4 - (2+1) = 1
    end
  end

  describe "encode/decode roundtrip" do
    test "instruction survives encode→decode" do
      insn = %Types{opcode: 0xB7, dst: 1, src: 0, offset: 0, imm: 42}
      binary = Types.encode(insn)
      decoded = Types.decode(binary)

      assert decoded.opcode == insn.opcode
      assert decoded.dst == insn.dst
      assert decoded.src == insn.src
      assert decoded.offset == insn.offset
      assert decoded.imm == insn.imm
    end

    test "negative offset survives roundtrip" do
      insn = %Types{opcode: 0x05, dst: 0, src: 0, offset: -5, imm: 0}
      assert Types.decode(Types.encode(insn)).offset == -5
    end

    test "negative immediate survives roundtrip" do
      insn = %Types{opcode: 0xB7, dst: 1, src: 0, offset: 0, imm: -100}
      assert Types.decode(Types.encode(insn)).imm == -100
    end
  end
end
