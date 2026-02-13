defmodule VaistoBpf.Types do
  @moduledoc """
  BPF type definitions: fixed-width integers, instruction encoding, registers, and opcodes.

  eBPF instructions are 8 bytes each:
    <<opcode::8, dst::4, src::4, offset::signed-16-little, imm::signed-32-little>>
  """

  import Bitwise

  # ============================================================================
  # Fixed-Width Types
  # ============================================================================

  @type bpf_type ::
          :u8 | :u16 | :u32 | :u64
          | :i8 | :i16 | :i32 | :i64
          | :bool

  @bpf_types [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64, :bool]

  def bpf_types, do: @bpf_types

  def bpf_type?(type), do: type in @bpf_types

  def signed?(:i8), do: true
  def signed?(:i16), do: true
  def signed?(:i32), do: true
  def signed?(:i64), do: true
  def signed?(_), do: false

  def width_bits(:u8), do: 8
  def width_bits(:i8), do: 8
  def width_bits(:bool), do: 8
  def width_bits(:u16), do: 16
  def width_bits(:i16), do: 16
  def width_bits(:u32), do: 32
  def width_bits(:i32), do: 32
  def width_bits(:u64), do: 64
  def width_bits(:i64), do: 64

  # ============================================================================
  # Registers
  # ============================================================================

  # r0 = return value / helper call return
  # r1-r5 = function arguments / scratch
  # r6-r9 = callee-saved
  # r10 = read-only frame pointer (stack)
  @r0 0
  @r1 1
  @r2 2
  @r3 3
  @r4 4
  @r5 5
  @r6 6
  @r7 7
  @r8 8
  @r9 9
  @r10 10

  def r0, do: @r0
  def r1, do: @r1
  def r2, do: @r2
  def r3, do: @r3
  def r4, do: @r4
  def r5, do: @r5
  def r6, do: @r6
  def r7, do: @r7
  def r8, do: @r8
  def r9, do: @r9
  def r10, do: @r10

  # Allocatable registers: r1-r9 (r0 = return, r10 = frame pointer)
  def allocatable_registers, do: [@r1, @r2, @r3, @r4, @r5, @r6, @r7, @r8, @r9]

  # ============================================================================
  # Instruction Classes (3 low bits of opcode)
  # ============================================================================

  @bpf_ld 0x00
  @bpf_ldx 0x01
  @bpf_st 0x02
  @bpf_stx 0x03
  @bpf_alu 0x04
  @bpf_jmp 0x05
  @bpf_jmp32 0x06
  @bpf_alu64 0x07

  def class_ld, do: @bpf_ld
  def class_ldx, do: @bpf_ldx
  def class_st, do: @bpf_st
  def class_stx, do: @bpf_stx
  def class_alu, do: @bpf_alu
  def class_jmp, do: @bpf_jmp
  def class_jmp32, do: @bpf_jmp32
  def class_alu64, do: @bpf_alu64

  # ============================================================================
  # ALU Operations (4 high bits of opcode)
  # ============================================================================

  @bpf_add 0x00
  @bpf_sub 0x10
  @bpf_mul 0x20
  @bpf_div 0x30
  @bpf_or 0x40
  @bpf_and 0x50
  @bpf_lsh 0x60
  @bpf_rsh 0x70
  @bpf_neg 0x80
  @bpf_mod 0x90
  @bpf_xor 0xA0
  @bpf_mov 0xB0
  @bpf_arsh 0xC0

  def alu_add, do: @bpf_add
  def alu_sub, do: @bpf_sub
  def alu_mul, do: @bpf_mul
  def alu_div, do: @bpf_div
  def alu_or, do: @bpf_or
  def alu_and, do: @bpf_and
  def alu_lsh, do: @bpf_lsh
  def alu_rsh, do: @bpf_rsh
  def alu_neg, do: @bpf_neg
  def alu_mod, do: @bpf_mod
  def alu_xor, do: @bpf_xor
  def alu_mov, do: @bpf_mov
  def alu_arsh, do: @bpf_arsh

  # ============================================================================
  # Source Operand Mode
  # ============================================================================

  @bpf_k 0x00
  @bpf_x 0x08

  # Immediate operand
  def src_imm, do: @bpf_k
  # Register operand
  def src_reg, do: @bpf_x

  # ============================================================================
  # Jump Operations (4 high bits of opcode)
  # ============================================================================

  @bpf_ja 0x00
  @bpf_jeq 0x10
  @bpf_jgt 0x20
  @bpf_jge 0x30
  @bpf_jset 0x40
  @bpf_jne 0x50
  @bpf_jsgt 0x60
  @bpf_jsge 0x70
  @bpf_jlt 0xA0
  @bpf_jle 0xB0
  @bpf_jslt 0xC0
  @bpf_jsle 0xD0
  @bpf_call 0x80
  @bpf_exit 0x90

  def jmp_ja, do: @bpf_ja
  def jmp_jeq, do: @bpf_jeq
  def jmp_jgt, do: @bpf_jgt
  def jmp_jge, do: @bpf_jge
  def jmp_jset, do: @bpf_jset
  def jmp_jne, do: @bpf_jne
  def jmp_jsgt, do: @bpf_jsgt
  def jmp_jsge, do: @bpf_jsge
  def jmp_jlt, do: @bpf_jlt
  def jmp_jle, do: @bpf_jle
  def jmp_jslt, do: @bpf_jslt
  def jmp_jsle, do: @bpf_jsle
  def jmp_call, do: @bpf_call
  def jmp_exit, do: @bpf_exit

  # ============================================================================
  # Memory Size Modes (2 bits in opcode for LD/ST)
  # ============================================================================

  @bpf_w 0x00
  @bpf_h 0x08
  @bpf_b 0x10
  @bpf_dw 0x18

  # 32-bit word
  def mem_w, do: @bpf_w
  # 16-bit half-word
  def mem_h, do: @bpf_h
  # 8-bit byte
  def mem_b, do: @bpf_b
  # 64-bit double-word
  def mem_dw, do: @bpf_dw

  @bpf_mem 0x60

  def mem_mode, do: @bpf_mem

  # ============================================================================
  # Instruction Struct
  # ============================================================================

  defstruct [:opcode, :dst, :src, :offset, :imm]

  @type t :: %__MODULE__{
          opcode: non_neg_integer(),
          dst: 0..15,
          src: 0..15,
          offset: integer(),
          imm: integer()
        }

  @doc """
  Encode an instruction struct to its 8-byte binary representation.
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{opcode: op, dst: dst, src: src, offset: off, imm: imm}) do
    <<op::8, (dst &&& 0xF) ||| ((src &&& 0xF) <<< 4)::8,
      off::signed-little-16, imm::signed-little-32>>
  end

  @doc """
  Decode an 8-byte binary into an instruction struct.
  """
  @spec decode(binary()) :: t()
  def decode(<<op::8, regs::8, off::signed-little-16, imm::signed-little-32>>) do
    %__MODULE__{
      opcode: op,
      dst: regs &&& 0xF,
      src: (regs >>> 4) &&& 0xF,
      offset: off,
      imm: imm
    }
  end

  # ============================================================================
  # Instruction Builders
  # ============================================================================

  @doc "MOV dst, imm (64-bit)"
  def mov64_imm(dst, imm) do
    %__MODULE__{opcode: @bpf_mov ||| @bpf_k ||| @bpf_alu64, dst: dst, src: 0, offset: 0, imm: imm}
  end

  @doc "MOV dst, src (64-bit)"
  def mov64_reg(dst, src) do
    %__MODULE__{opcode: @bpf_mov ||| @bpf_x ||| @bpf_alu64, dst: dst, src: src, offset: 0, imm: 0}
  end

  @doc "ALU64 dst, imm"
  def alu64_imm(op, dst, imm) do
    %__MODULE__{opcode: op ||| @bpf_k ||| @bpf_alu64, dst: dst, src: 0, offset: 0, imm: imm}
  end

  @doc "ALU64 dst, src"
  def alu64_reg(op, dst, src) do
    %__MODULE__{opcode: op ||| @bpf_x ||| @bpf_alu64, dst: dst, src: src, offset: 0, imm: 0}
  end

  @doc "ALU32 dst, imm"
  def alu32_imm(op, dst, imm) do
    %__MODULE__{opcode: op ||| @bpf_k ||| @bpf_alu, dst: dst, src: 0, offset: 0, imm: imm}
  end

  @doc "ALU32 dst, src"
  def alu32_reg(op, dst, src) do
    %__MODULE__{opcode: op ||| @bpf_x ||| @bpf_alu, dst: dst, src: src, offset: 0, imm: 0}
  end

  @doc "Conditional jump: if dst OP imm goto +offset"
  def jmp_imm(op, dst, imm, offset) do
    %__MODULE__{opcode: op ||| @bpf_k ||| @bpf_jmp, dst: dst, src: 0, offset: offset, imm: imm}
  end

  @doc "Conditional jump: if dst OP src goto +offset"
  def jmp_reg(op, dst, src, offset) do
    %__MODULE__{opcode: op ||| @bpf_x ||| @bpf_jmp, dst: dst, src: src, offset: offset, imm: 0}
  end

  @doc "Unconditional jump: goto +offset"
  def ja(offset) do
    %__MODULE__{opcode: @bpf_ja ||| @bpf_jmp, dst: 0, src: 0, offset: offset, imm: 0}
  end

  @doc "Exit program (return r0)"
  def exit_insn do
    %__MODULE__{opcode: @bpf_exit ||| @bpf_jmp, dst: 0, src: 0, offset: 0, imm: 0}
  end

  @doc "Call BPF helper function"
  def call_helper(helper_id) do
    %__MODULE__{opcode: @bpf_call ||| @bpf_jmp, dst: 0, src: 0, offset: 0, imm: helper_id}
  end

  @doc """
  LD_IMM64 with pseudo-map-FD (src_reg=1).

  Returns `{insn1, insn2}` — a 16-byte wide instruction pair.
  The immediate holds the map index; libbpf patches it to the real FD.
  """
  def ld_map_fd(dst, map_index) do
    # Opcode: BPF_LD | BPF_DW | BPF_IMM = 0x18, src_reg=1 for pseudo-map-FD
    insn1 = %__MODULE__{opcode: @bpf_ld ||| @bpf_dw ||| 0x00, dst: dst, src: 1, offset: 0, imm: map_index}
    insn2 = %__MODULE__{opcode: 0, dst: 0, src: 0, offset: 0, imm: 0}
    {insn1, insn2}
  end

  @doc "Store from register to memory: *(size *)(dst + offset) = src"
  def stx_mem(size, dst, src, offset) do
    %__MODULE__{opcode: size ||| @bpf_mem ||| @bpf_stx, dst: dst, src: src, offset: offset, imm: 0}
  end

  @doc "Load from memory to register: dst = *(size *)(src + offset)"
  def ldx_mem(size, dst, src, offset) do
    %__MODULE__{opcode: size ||| @bpf_mem ||| @bpf_ldx, dst: dst, src: src, offset: offset, imm: 0}
  end
end
