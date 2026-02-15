defmodule VaistoBpf.RegisterAllocatorTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias VaistoBpf.Types

  defp decode(bin), do: Types.decode(bin)

  defp compile!(source) do
    {:ok, instructions} = VaistoBpf.compile_source(source)
    Enum.map(instructions, &decode/1)
  end

  @call_opcode Types.jmp_call() ||| Types.class_jmp()
  @exit_opcode Types.jmp_exit() ||| Types.class_jmp()

  # ============================================================================
  # map_update_elem end-to-end (previously overflowed)
  # ============================================================================

  describe "map_update_elem end-to-end" do
    test "4-arg helper with 2 ptr_args compiles" do
      instructions = compile!("""
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_update_elem [:u64 :u64 :u64 :u64] :u64)
      (defn update [key :u64 val :u64] :u64
        (bpf/map_update_elem counters key val 0))
      """)

      call_insn = Enum.find(instructions, &(&1.opcode == @call_opcode))
      assert call_insn != nil
      assert call_insn.imm == 2
    end
  end

  # ============================================================================
  # Arithmetic chains (register reuse for temporaries)
  # ============================================================================

  describe "arithmetic chains" do
    test "deeply nested (+ (+ (+ ...))) compiles" do
      # 6-deep nesting: each intermediate is a temporary that should be freed
      instructions = compile!("""
      (defn deep [a :u64 b :u64] :u64
        (+ (+ (+ (+ (+ (+ a b) b) b) b) b) b))
      """)

      assert List.last(instructions).opcode == @exit_opcode
    end

    test "parallel arithmetic expressions compile" do
      # Multiple independent additions that should reuse registers
      instructions = compile!("""
      (defn parallel [x :u64 y :u64] :u64
        (+ (+ x y) (+ x y)))
      """)

      assert List.last(instructions).opcode == @exit_opcode
    end
  end

  # ============================================================================
  # Let binding chains
  # ============================================================================

  describe "let binding chains" do
    test "6+ chained let bindings compile" do
      instructions = compile!("""
      (defn chain [x :u64] :u64
        (let [a (+ x 1)
              b (+ a 2)
              c (+ b 3)
              d (+ c 4)
              e (+ d 5)
              f (+ e 6)]
          f))
      """)

      assert List.last(instructions).opcode == @exit_opcode
    end
  end

  # ============================================================================
  # Nested conditionals
  # ============================================================================

  describe "nested if with comparisons" do
    test "nested conditions don't overflow" do
      instructions = compile!("""
      (defn nested [x :u64 y :u64] :u64
        (if (> x y)
          (if (> x 10) x y)
          (if (> y 10) y x)))
      """)

      assert List.last(instructions).opcode == @exit_opcode
    end
  end

  # ============================================================================
  # Register reuse after helper call
  # ============================================================================

  describe "register reuse after helper call" do
    test "computation after helper call reuses r1-r5" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (defn compute [] :u64
        (let [t (bpf/ktime_get_ns)]
          (+ (+ (+ t 1) 2) 3)))
      """)

      call_idx = Enum.find_index(instructions, &(&1.opcode == @call_opcode))
      assert call_idx != nil
      assert List.last(instructions).opcode == @exit_opcode
    end

    test "two helper calls with arithmetic between them" do
      instructions = compile!("""
      (extern bpf:ktime_get_ns [] :u64)
      (extern bpf:get_current_pid_tgid [] :u64)
      (defn both [] :u64
        (+ (bpf/ktime_get_ns) (bpf/get_current_pid_tgid)))
      """)

      calls = Enum.filter(instructions, &(&1.opcode == @call_opcode))
      assert length(calls) == 2
    end
  end
end
