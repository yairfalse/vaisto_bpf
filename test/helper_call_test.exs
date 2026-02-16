defmodule VaistoBpf.HelperCallTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias VaistoBpf.Types

  # Decode helper: binary instruction → struct
  defp decode(bin), do: Types.decode(bin)

  # Compile helper: source string → instruction structs
  defp compile!(source) do
    {:ok, instructions} = VaistoBpf.compile_source(source)
    Enum.map(instructions, &decode/1)
  end

  # Opcode constants for assertions
  @call_opcode Types.jmp_call() ||| Types.class_jmp()
  @mov64_reg_opcode Types.alu_mov() ||| Types.src_reg() ||| Types.class_alu64()
  @exit_opcode Types.jmp_exit() ||| Types.class_jmp()

  # ============================================================================
  # Happy Path: Zero-arg helper
  # ============================================================================

  describe "zero-arg helper (ktime_get_ns)" do
    test "emits CALL instruction with correct helper ID" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (defn get_time [] :u64 (bpf/ktime_get_ns))
      """)

      call_insn = Enum.find(instructions, &(&1.opcode == @call_opcode))
      assert call_insn != nil
      assert call_insn.imm == 5
    end

    test "produces valid instruction sequence" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (defn get_time [] :u64 (bpf/ktime_get_ns))
      """)

      # Should end with EXIT
      assert List.last(instructions).opcode == @exit_opcode

      # Should have a MOV to r0 before exit (return value)
      pre_exit = Enum.at(instructions, -2)
      assert pre_exit.opcode == @mov64_reg_opcode
      assert pre_exit.dst == Types.r0()
    end
  end

  # ============================================================================
  # Happy Path: Multi-arg helper
  # ============================================================================

  describe "multi-arg helper (map_lookup_elem)" do
    test "emits CALL with correct ID and arg setup" do
      instructions = compile!("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(Some v) (bpf/load_u64 v 0)]
          [(None) 0]))
      """)

      call_insn = Enum.find(instructions, &(&1.opcode == @call_opcode))
      assert call_insn != nil
      assert call_insn.imm == 1
    end
  end

  # ============================================================================
  # Happy Path: Helper result in arithmetic
  # ============================================================================

  describe "helper result in arithmetic" do
    test "(+ (bpf/ktime_get_ns) 1) compiles to call then add" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (defn time_plus_one [] :u64 (+ (bpf/ktime_get_ns) 1))
      """)

      call_idx = Enum.find_index(instructions, &(&1.opcode == @call_opcode))
      assert call_idx != nil

      # After the call, there should be ALU add instruction
      rest = Enum.drop(instructions, call_idx + 1)
      has_add = Enum.any?(rest, fn insn ->
        # ALU64_IMM ADD = 0x07
        insn.opcode == (Types.alu_add() ||| Types.src_imm() ||| Types.class_alu64()) and
          insn.imm == 1
      end)
      assert has_add, "expected ALU64 ADD IMM 1 after CALL"
    end
  end

  # ============================================================================
  # Happy Path: Variable preservation across helper call
  # ============================================================================

  describe "variable preservation across helper call" do
    test "parameter survives a helper call via callee-saved register spill" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (defn f [x :u64] :u64
        (let [t (bpf/ktime_get_ns)]
          (+ x t)))
      """)

      # x (in r1) should be spilled to r6 before the call
      first_insn = List.first(instructions)
      assert first_insn.opcode == @mov64_reg_opcode
      assert first_insn.dst == Types.r6()
      assert first_insn.src == Types.r1()

      # Then CALL
      call_idx = Enum.find_index(instructions, &(&1.opcode == @call_opcode))
      assert call_idx != nil

      # After call, x is read from r6 (callee-saved) for the addition
      rest = Enum.drop(instructions, call_idx + 1)
      uses_r6 = Enum.any?(rest, fn insn -> insn.src == Types.r6() end)
      assert uses_r6, "expected x to be read from callee-saved r6 after helper call"
    end
  end

  # ============================================================================
  # Happy Path: Multiple helper calls
  # ============================================================================

  describe "multiple helper calls in one function" do
    test "two helper calls both emit CALL instructions" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (extern bpf:get_current_pid_tgid [] :u64)
      (defn f [] :u64
        (+ (bpf/ktime_get_ns) (bpf/get_current_pid_tgid)))
      """)

      call_insns = Enum.filter(instructions, &(&1.opcode == @call_opcode))
      assert length(call_insns) == 2
      assert Enum.at(call_insns, 0).imm == 5   # ktime_get_ns
      assert Enum.at(call_insns, 1).imm == 14  # get_current_pid_tgid
    end
  end

  # ============================================================================
  # Happy Path: Different return type (u32)
  # ============================================================================

  describe "helper with u32 return type" do
    test "get_smp_processor_id compiles" do
      instructions = compile!("""
      (extern bpf:get_smp_processor_id [] :u32)
      (defn cpu [] :u32 (bpf/get_smp_processor_id))
      """)

      call_insn = Enum.find(instructions, &(&1.opcode == @call_opcode))
      assert call_insn.imm == 8
    end
  end

  # ============================================================================
  # Error Cases
  # ============================================================================

  describe "error: unknown helper" do
    test "rejects call to undeclared helper" do
      result = VaistoBpf.compile_source("""
      (defn f [] :u64 (bpf/nonexistent))
      """)

      assert {:error, err} = result
      assert err.message =~ "unknown helper"
    end
  end

  describe "error: wrong argument count" do
    test "rejects too few args" do
      result = VaistoBpf.compile_source("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [x :u64] :u64 (bpf/map_lookup_elem x))
      """)

      assert {:error, err} = result
      assert err.message =~ "expects 2 arguments, got 1"
    end

    test "rejects too many args" do
      result = VaistoBpf.compile_source("""
      (extern bpf:ktime_get_ns [] :u64)
      (defn f [x :u64] :u64 (bpf/ktime_get_ns x))
      """)

      assert {:error, err} = result
      assert err.message =~ "expects 0 arguments, got 1"
    end
  end

  describe "error: wrong argument types" do
    test "rejects bool arg where u64 expected" do
      result = VaistoBpf.compile_source("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [] :u64 (bpf/map_lookup_elem true true))
      """)

      assert {:error, err} = result
      assert err.message =~ "type mismatch"
    end
  end

  # ============================================================================
  # End-to-End via compile_source/1
  # ============================================================================

  describe "end-to-end compile_source/1" do
    test "full pipeline from source to bytecode" do
      source = """
      (extern bpf:ktime_get_ns [] :u64)
      (defn get_time [] :u64 (bpf/ktime_get_ns))
      """

      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert Enum.all?(instructions, &is_binary/1)
      assert Enum.all?(instructions, &(byte_size(&1) == 8))

      # Verify CALL with imm=5 is in the bytecode
      has_call = Enum.any?(instructions, fn bin ->
        decoded = Types.decode(bin)
        decoded.opcode == @call_opcode and decoded.imm == 5
      end)
      assert has_call
    end
  end
end
