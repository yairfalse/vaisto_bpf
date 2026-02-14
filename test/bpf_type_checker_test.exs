defmodule VaistoBpf.BpfTypeCheckerTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.BpfTypeChecker
  alias VaistoBpf.Preprocessor
  alias Vaisto.Error

  # Helper: parse a BPF source string into normalized AST
  defp parse_bpf(source) do
    source
    |> Preprocessor.preprocess_source()
    |> Vaisto.Parser.parse()
    |> Preprocessor.normalize_ast()
  end

  describe "arithmetic — same type" do
    test "u64 + u64 passes" do
      ast = parse_bpf("(defn add [x :u64 y :u64] :u64 (+ x y))")
      assert {:ok, {:fn, [:u64, :u64], :u64}, typed_ast} = BpfTypeChecker.check(ast)
      {:defn, :add, [:x, :y], body, {:fn, [:u64, :u64], :u64}} = typed_ast
      {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64} = body
    end

    test "u32 - u32 passes" do
      ast = parse_bpf("(defn sub [a :u32 b :u32] :u32 (- a b))")
      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end

    test "i64 * i64 passes" do
      ast = parse_bpf("(defn mul [x :i64 y :i64] :i64 (* x y))")
      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end

    test "all arithmetic ops work" do
      for op <- ["+", "-", "*", "div", "rem"] do
        ast = parse_bpf("(defn f [x :u64 y :u64] :u64 (#{op} x y))")
        assert {:ok, _, _} = BpfTypeChecker.check(ast), "#{op} should pass"
      end
    end
  end

  describe "arithmetic — mixed types rejected" do
    test "u64 + u32 fails" do
      ast = parse_bpf("(defn f [x :u64 y :u32] :u64 (+ x y))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "same type"
    end

    test "u64 + bool fails" do
      ast = parse_bpf("(defn f [x :u64 y :bool] :u64 (+ x y))")
      assert {:error, %Error{}} = BpfTypeChecker.check(ast)
    end
  end

  describe "bitwise operations" do
    test "band/bor/bxor/bsl/bsr pass with same types" do
      for op <- ["band", "bor", "bxor", "bsl", "bsr"] do
        ast = parse_bpf("(defn f [x :u64 y :u64] :u64 (#{op} x y))")
        assert {:ok, _, _} = BpfTypeChecker.check(ast), "#{op} should pass"
      end
    end

    test "bitwise rejects mixed types" do
      ast = parse_bpf("(defn f [x :u64 y :u32] :u64 (band x y))")
      assert {:error, %Error{}} = BpfTypeChecker.check(ast)
    end
  end

  describe "comparisons" do
    test "== on same types returns bool" do
      ast = parse_bpf("(defn eq [x :u64 y :u64] :bool (== x y))")
      assert {:ok, {:fn, [:u64, :u64], :bool}, typed} = BpfTypeChecker.check(ast)
      {:defn, :eq, _, body, _} = typed
      {:call, :==, _, :bool} = body
    end

    test "all comparison ops work" do
      for op <- ["==", "!=", ">", "<", ">=", "<="] do
        ast = parse_bpf("(defn f [x :u64 y :u64] :bool (#{op} x y))")
        assert {:ok, _, _} = BpfTypeChecker.check(ast), "#{op} should pass"
      end
    end

    test "comparison rejects different types" do
      ast = parse_bpf("(defn f [x :u64 y :u32] :bool (== x y))")
      assert {:error, %Error{}} = BpfTypeChecker.check(ast)
    end
  end

  describe "integer literal inference" do
    test "literal infers type from other operand" do
      ast = parse_bpf("(defn inc [x :u64] :u64 (+ x 1))")
      assert {:ok, _, typed} = BpfTypeChecker.check(ast)
      {:defn, :inc, _, {:call, :+, [_, {:lit, :int, 1}], :u64}, _} = typed
    end

    test "literal on left side infers from right" do
      ast = parse_bpf("(defn f [x :u64] :u64 (+ 1 x))")
      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end

    test "literal infers from return type" do
      ast = parse_bpf("(defn const [] :u64 42)")
      assert {:ok, {:fn, [], :u64}, typed} = BpfTypeChecker.check(ast)
      {:defn, :const, [], {:lit, :int, 42}, {:fn, [], :u64}} = typed
    end

    test "literal without context fails" do
      # Two literals with no type context — can't determine type
      # We need to be inside a context where the type isn't propagated
      # A standalone let with literal and no usage would need context
      ast = parse_bpf("(defn f [x :u64] :u64 (let [y 42] x))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "type context"
    end
  end

  describe "if expression" do
    test "well-typed if passes" do
      ast = parse_bpf("(defn max [a :u64 b :u64] :u64 (if (> a b) a b))")
      assert {:ok, _, typed} = BpfTypeChecker.check(ast)
      {:defn, :max, _, {:if, _, _, _, :u64}, _} = typed
    end

    test "branches must have same type" do
      # This requires a setup where branches differ — one returns u64, other u32
      # We'll use two params of different types
      ast = parse_bpf("(defn f [a :u64 b :u32 c :bool] :u64 (if c a b))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "different types"
    end
  end

  describe "let bindings" do
    test "let with typed expression passes" do
      ast = parse_bpf("(defn double [x :u64] :u64 (let [y (+ x x)] y))")
      assert {:ok, _, typed} = BpfTypeChecker.check(ast)
      {:defn, :double, _, {:let, _, {:var, :y, :u64}, :u64}, _} = typed
    end
  end

  describe "return type mismatch" do
    test "body type must match declared return type" do
      ast = parse_bpf("(defn f [x :u64 y :u64] :bool (+ x y))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "return type mismatch"
    end
  end

  describe "rejected BEAM types" do
    test "rejects :int params" do
      ast = parse_bpf("(defn f [x :int] :int (+ x 1))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "not supported"
    end

    test "rejects :float params" do
      ast = parse_bpf("(defn f [x :float] :float x)")
      assert {:error, %Error{}} = BpfTypeChecker.check(ast)
    end

    test "rejects :string params" do
      ast = parse_bpf("(defn f [x :string] :string x)")
      assert {:error, %Error{}} = BpfTypeChecker.check(ast)
    end

    test "rejects :any params" do
      ast = parse_bpf("(defn f [x :any] :any x)")
      assert {:error, %Error{}} = BpfTypeChecker.check(ast)
    end
  end

  describe "rejected constructs" do
    test "rejects anonymous functions" do
      ast = parse_bpf("(defn f [x :u64] :u64 (fn [y] y))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "anonymous"
    end
  end

  describe "multi-function module" do
    test "module with ns and multiple defns" do
      ast = parse_bpf("""
      (ns Math)
      (defn add [x :u64 y :u64] :u64 (+ x y))
      (defn sub [a :u64 b :u64] :u64 (- a b))
      """)

      assert {:ok, {:module, _}, {:module, typed_forms}} = BpfTypeChecker.check(ast)
      assert length(typed_forms) == 3

      [{:ns, :Math}, {:defn, :add, _, _, _}, {:defn, :sub, _, _, _}] = typed_forms
    end

    test "functions can call each other" do
      ast = parse_bpf("""
      (ns Calc)
      (defn inc [x :u64] :u64 (+ x 1))
      (defn add_two [x :u64] :u64 (inc (inc x)))
      """)

      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end
  end

  describe "memory access builtins" do
    test "bpf/load_u64 type-checks without extern" do
      ast = parse_bpf("(defn read_val [ptr :u64] :u64 (bpf/load_u64 ptr 0))")
      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end

    test "bpf/store_u32 type-checks correctly" do
      ast = parse_bpf("(defn write_val [ptr :u64 val :u32] :unit (bpf/store_u32 ptr 4 val))")
      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end

    test "bpf/load_u32 returns u32" do
      ast = parse_bpf("(defn read32 [ptr :u64] :u32 (bpf/load_u32 ptr 8))")
      assert {:ok, {:fn, [:u64], :u32}, _} = BpfTypeChecker.check(ast)
    end

    test "wrong argument count is rejected" do
      ast = parse_bpf("(defn bad [ptr :u64] :u64 (bpf/load_u64 ptr))")
      assert {:error, %Error{message: msg}} = BpfTypeChecker.check(ast)
      assert msg =~ "expects 2 arguments"
    end

    test "all load sizes type-check" do
      for {size, ret} <- [{"u64", "u64"}, {"u32", "u32"}, {"u16", "u16"}, {"u8", "u8"}] do
        ast = parse_bpf("(defn f [ptr :u64] :#{ret} (bpf/load_#{size} ptr 0))")
        assert {:ok, _, _} = BpfTypeChecker.check(ast), "load_#{size} should pass"
      end
    end

    test "all store sizes type-check" do
      for size <- ["u64", "u32", "u16", "u8"] do
        ast = parse_bpf("(defn f [ptr :u64 val :#{size}] :unit (bpf/store_#{size} ptr 0 val))")
        assert {:ok, _, _} = BpfTypeChecker.check(ast), "store_#{size} should pass"
      end
    end
  end

  describe "deftype" do
    test "record with BPF fields passes" do
      ast = parse_bpf("""
      (deftype Point [x :u32 y :u32])
      (defn origin [] :u32 0)
      """)

      assert {:ok, _, _} = BpfTypeChecker.check(ast)
    end
  end
end
