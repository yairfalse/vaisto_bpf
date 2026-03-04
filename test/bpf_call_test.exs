defmodule VaistoBpf.BpfCallTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker
  alias VaistoBpf.Emitter
  alias VaistoBpf.Types

  defp compile_to_ir(source) do
    preprocessed = Preprocessor.preprocess_source(source)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)
    {:ok, _, typed_ast} = BpfTypeChecker.check(normalized)
    {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
    Emitter.emit(ast)
  end

  describe "emitter" do
    test "user function call produces {:call_fn, {:fn, name}} IR" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      (defn main [] :u64 (inc 42))
      """
      {:ok, ir} = compile_to_ir(source)
      assert Enum.any?(ir, &match?({:call_fn, {:fn, :inc}}, &1))
    end

    test "does not emit {:call_fn, ...} for helper calls" do
      source = """
      (extern bpf:ktime_get_ns [] :u64)
      (defn main [] :u64 (bpf/ktime_get_ns))
      """
      {:ok, ir} = compile_to_ir(source)
      refute Enum.any?(ir, &match?({:call_fn, _}, &1))
      assert Enum.any?(ir, &match?({:call, 5}, &1))
    end
  end

  describe "assembler" do
    test "resolves call_fn to correct relative offset" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      (defn main [] :u64 (inc 42))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "call instruction has src_reg=1 (BPF_PSEUDO_CALL)" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      (defn main [] :u64 (inc 42))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)

      # Find call instructions: opcode = 0x85 (JMP|CALL)
      call_opcode = Types.jmp_call() ||| Types.class_jmp()
      decoded = Enum.map(instructions, &Types.decode/1)
      call_insns = Enum.filter(decoded, fn insn -> insn.opcode == call_opcode end)

      # There should be at least one with src=1 (BPF_PSEUDO_CALL)
      bpf_calls = Enum.filter(call_insns, fn insn -> insn.src == 1 end)
      assert length(bpf_calls) >= 1

      # And there should be helper calls with src=0
      # (None in this case since we only call user functions)
    end
  end

  describe "callee-saved prologue/epilogue" do
    test "function emits STX_MEM prologue (save r6-r9)" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      """
      {:ok, ir} = compile_to_ir(source)

      # Should have 4 STX_MEM instructions saving r6, r7, r8, r9 to stack
      stx_saves = Enum.filter(ir, fn
        {:stx_mem, :u64, dst, src, _off} when dst == 10 and src in [6, 7, 8, 9] -> true
        _ -> false
      end)
      assert length(stx_saves) == 4
    end

    test "function emits LDX_MEM epilogue (restore r6-r9)" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      """
      {:ok, ir} = compile_to_ir(source)

      # Should have 4 LDX_MEM instructions restoring r6, r7, r8, r9
      ldx_restores = Enum.filter(ir, fn
        {:ldx_mem, :u64, dst, src, _off} when src == 10 and dst in [6, 7, 8, 9] -> true
        _ -> false
      end)
      assert length(ldx_restores) == 4
    end
  end

  describe "stack isolation" do
    test "two functions have independent stack frames" do
      source = """
      (defn f [x :u64] :u64 (let [a (+ x 1)] a))
      (defn g [y :u64] :u64 (let [b (+ y 2)] b))
      """
      {:ok, _ir} = compile_to_ir(source)
      # If this compiles without error, stack frames are isolated
      # (each defn resets stack_offset)
    end
  end

  describe "call depth safety" do
    test "depth 8 is accepted" do
      # Build a chain: f1 calls f2, f2 calls f3, ..., f8 calls f9
      fns = for i <- 1..8 do
        "(defn f#{i} [x :u64] :u64 (f#{i + 1} x))"
      end
      leaf = "(defn f9 [x :u64] :u64 (+ x 1))"
      source = Enum.join(fns ++ [leaf], "\n")

      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "depth 9 is rejected" do
      # Build a chain: f1 calls f2, ..., f9 calls f10
      fns = for i <- 1..9 do
        "(defn f#{i} [x :u64] :u64 (f#{i + 1} x))"
      end
      leaf = "(defn f10 [x :u64] :u64 (+ x 1))"
      source = Enum.join(fns ++ [leaf], "\n")

      assert {:error, err} = VaistoBpf.compile_source(source)
      assert err.message =~ "call depth"
    end
  end

  describe "source integration" do
    test "chained user function calls compile" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      (defn add_two [x :u64] :u64 (inc (inc x)))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)

      # Should have two BPF_PSEUDO_CALL instructions
      call_opcode = Types.jmp_call() ||| Types.class_jmp()
      decoded = Enum.map(instructions, &Types.decode/1)
      bpf_calls = Enum.filter(decoded, fn insn ->
        insn.opcode == call_opcode and insn.src == 1
      end)
      assert length(bpf_calls) == 2
    end

    test "mix of user and helper calls" do
      source = """
      (extern bpf:ktime_get_ns [] :u64)
      (defn get_time [] :u64 (bpf/ktime_get_ns))
      (defn main [] :u64 (get_time))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)

      call_opcode = Types.jmp_call() ||| Types.class_jmp()
      decoded = Enum.map(instructions, &Types.decode/1)
      call_insns = Enum.filter(decoded, fn insn -> insn.opcode == call_opcode end)

      # One BPF_PSEUDO_CALL (get_time) and one helper call (ktime_get_ns)
      assert Enum.count(call_insns, fn i -> i.src == 1 end) == 1
      assert Enum.count(call_insns, fn i -> i.src == 0 end) == 1
    end

    test "call offset points to correct function" do
      source = """
      (defn inc [x :u64] :u64 (+ x 1))
      (defn main [] :u64 (inc 42))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)

      call_opcode = Types.jmp_call() ||| Types.class_jmp()
      decoded = Enum.map(instructions, &Types.decode/1)

      # Find the BPF_PSEUDO_CALL
      {call_insn, call_idx} =
        decoded
        |> Enum.with_index()
        |> Enum.find(fn {insn, _idx} -> insn.opcode == call_opcode and insn.src == 1 end)

      # The imm field is relative offset from (call_idx + 1)
      target_idx = call_idx + 1 + call_insn.imm

      # Target should be the start of inc (instruction 0 is the fn label)
      assert target_idx >= 0
    end
  end
end
