defmodule VaistoBpf.LoopTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker
  alias VaistoBpf.Emitter

  describe "preprocessor normalization" do
    test "for-range is normalized to {:for_range, ...}" do
      source = "(defn foo [] :u64 (for-range i 0 10 i))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      # The for-range should be inside the defn body
      {:defn, :foo, [], body, :u64, _loc} = normalized
      assert {:for_range, :i, 0, 10, :i, _} = body
    end

    test "for-range with expressions" do
      source = "(defn foo [n :u64] :u64 (for-range i 0 n (+ i 1)))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:defn, :foo, [{:n, :u64}], body, :u64, _loc} = normalized
      {:for_range, :i, 0, :n, {:call, :+, _, _}, _} = body
    end
  end

  describe "type checker" do
    test "for-range with same integer types passes" do
      source = "(defn foo [] :u64 (do (for-range i 0 10 i) 0))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      assert {:ok, _, _} = BpfTypeChecker.check(normalized)
    end

    test "for-range result is :unit" do
      source = "(defn foo [] :unit (for-range i 0 10 i))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      assert {:ok, _, _} = BpfTypeChecker.check(normalized)
    end

    test "for-range with mismatched start/end types rejected" do
      # Force the types: start is u32 variable, end is u64 variable
      source = """
      (defn foo [a :u32 b :u64] :unit
        (for-range i a b i))
      """
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      assert {:error, _} = BpfTypeChecker.check(normalized)
    end

    test "loop variable is in scope within body" do
      source = "(defn foo [] :unit (for-range i 0 10 (+ i 1)))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      assert {:ok, _, _} = BpfTypeChecker.check(normalized)
    end

    test "for-range typed AST includes iterator type" do
      source = "(defn foo [] :unit (for-range i 0 10 i))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:ok, _, typed_ast} = BpfTypeChecker.check(normalized)

      # Single-form parse produces a single typed form (not module wrapper)
      {:defn, :foo, [], typed_body, _fn_type} = typed_ast

      # Typed body should be {:for_range, var, start, end, body, iter_type}
      assert {:for_range, :i, _, _, _, iter_type} = typed_body
      assert iter_type in [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64]
    end
  end

  describe "emitter" do
    test "produces JGE and JA instructions" do
      source = "(defn foo [] :unit (for-range i 0 10 i))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:ok, _, typed_ast} = BpfTypeChecker.check(normalized)
      {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
      {:ok, ir} = Emitter.emit(ast)

      # Should contain JGE (conditional) and JA (backward jump)
      assert Enum.any?(ir, &match?({:jmp_reg, :jge, _, _, _}, &1))
      assert Enum.any?(ir, &match?({:ja, _}, &1))
      # Should contain ALU ADD for iterator increment
      assert Enum.any?(ir, &match?({:alu64_imm, :add, _, 1}, &1))
    end

    test "assembles with backward jump (negative offset)" do
      source = "(defn foo [] :unit (for-range i 0 10 i))"

      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0

      # Verify a JA instruction has a negative offset (backward jump)
      decoded = Enum.map(instructions, &VaistoBpf.Types.decode/1)
      ja_opcode = VaistoBpf.Types.jmp_ja() ||| VaistoBpf.Types.class_jmp()
      ja_insns = Enum.filter(decoded, fn insn -> insn.opcode == ja_opcode end)
      # There should be at least one backward jump
      assert Enum.any?(ja_insns, fn insn -> insn.offset < 0 end)
    end
  end

  describe "source integration" do
    test "for-range compiles end-to-end" do
      source = """
      (defn count [n :u64] :u64
        (do (for-range i 0 n i) 0))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "for-range with arithmetic body compiles" do
      source = """
      (defn sum_range [n :u64] :u64
        (do (for-range i 0 n (+ i 1)) 0))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
    end
  end
end
