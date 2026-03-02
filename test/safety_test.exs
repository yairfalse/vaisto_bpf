defmodule VaistoBpf.SafetyTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Safety

  # Helper to build typed AST fragments
  defp div_node(left, right, type \\ :u64),
    do: {:call, :div, [left, right], type}

  defp rem_node(left, right, type \\ :u64),
    do: {:call, :rem, [left, right], type}

  defp shift_node(op, left, right, type \\ :u64),
    do: {:call, op, [left, right], type}

  defp lit(val), do: {:lit, :int, val}
  defp var(name, type \\ :u64), do: {:var, name, type}

  # -- A1: Division by literal zero --

  describe "division by literal zero" do
    test "rejects div by literal 0" do
      ast = div_node(var(:x), lit(0))
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "division by zero"
    end

    test "rejects rem by literal 0" do
      ast = rem_node(var(:x), lit(0))
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "division by zero"
    end

    test "allows div by non-zero literal" do
      ast = div_node(var(:x), lit(3))
      assert :ok = Safety.check(ast)
    end

    test "allows div by variable (can't check at compile time)" do
      ast = div_node(var(:x), var(:y))
      assert :ok = Safety.check(ast)
    end

    test "catches nested div-by-zero" do
      # (+ (div x 0) 1) — div-by-zero inside an expression
      inner = div_node(var(:x), lit(0))
      ast = {:call, :+, [inner, lit(1)], :u64}
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "division by zero"
    end
  end

  # -- A3: Shift amount validation --

  describe "shift amount validation" do
    test "rejects bsl by amount >= type width" do
      ast = shift_node(:bsl, var(:x), lit(64), :u64)
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "shift amount 64 exceeds type width of 64 bits"
    end

    test "rejects bsr by amount >= type width" do
      ast = shift_node(:bsr, var(:x), lit(32), :u32)
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "shift amount 32 exceeds type width of 32 bits"
    end

    test "rejects negative shift amount" do
      ast = shift_node(:bsl, var(:x), lit(-1), :u64)
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "shift amount -1 is negative"
    end

    test "allows shift by valid amount" do
      ast = shift_node(:bsl, var(:x), lit(31), :u32)
      assert :ok = Safety.check(ast)
    end

    test "allows shift by 0" do
      ast = shift_node(:bsr, var(:x), lit(0), :u64)
      assert :ok = Safety.check(ast)
    end

    test "allows shift by variable" do
      ast = shift_node(:bsl, var(:x), var(:y))
      assert :ok = Safety.check(ast)
    end

    test "validates against 8-bit width" do
      ast = shift_node(:bsl, var(:x, :u8), lit(8), :u8)
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "8 bits"
    end
  end

  # -- A4: Negative/empty loop bounds --

  describe "for-range loop bounds" do
    test "warns when start >= end (empty loop)" do
      ast = {:for_range, :i, lit(5), lit(5), {:unit}, :u64}
      assert {:ok, warnings} = Safety.check_with_warnings(ast)
      assert [{:warning, msg}] = warnings
      assert msg =~ "will never execute"
    end

    test "warns when start > end" do
      ast = {:for_range, :i, lit(10), lit(3), {:unit}, :u64}
      assert {:ok, warnings} = Safety.check_with_warnings(ast)
      assert [{:warning, msg}] = warnings
      assert msg =~ "will never execute"
    end

    test "no warning for valid range" do
      ast = {:for_range, :i, lit(0), lit(10), {:unit}, :u64}
      assert {:ok, []} = Safety.check_with_warnings(ast)
    end

    test "no warning when bounds are variables" do
      ast = {:for_range, :i, var(:start), var(:end_val), {:unit}, :u64}
      assert {:ok, []} = Safety.check_with_warnings(ast)
    end
  end

  # -- Integration: pipeline integration --

  describe "pipeline integration" do
    test "compile_source rejects div by zero" do
      source = ~s|(defn bad [x :u64] :u64 (div x 0))|
      assert {:error, %{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "division by zero"
    end

    test "compile_source allows safe code" do
      source = ~s|(defn good [x :u64 y :u64] :u64 (div x y))|
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "compile_source rejects bad shift in nested expression" do
      source = ~s|(defn bad [x :u32] :u32 (bsl x 32))|
      assert {:error, %{message: msg}} = VaistoBpf.compile_source(source)
      assert msg =~ "shift amount"
    end
  end

  # -- Edge cases --

  describe "edge cases" do
    test "handles list of definitions" do
      defn1 = {:defn, :foo, [{:x, :u64}], div_node(var(:x), lit(2)), :u64}
      defn2 = {:defn, :bar, [{:y, :u64}], div_node(var(:y), lit(0)), :u64}
      assert {:error, %{message: msg}} = Safety.check([defn1, defn2])
      assert msg =~ "division by zero"
    end

    test "handles let bindings" do
      body = {:let, [{:y, div_node(var(:x), lit(0))}], var(:y)}
      assert {:error, %{message: msg}} = Safety.check(body)
      assert msg =~ "division by zero"
    end

    test "handles if expressions" do
      then_expr = div_node(var(:x), lit(0))
      ast = {:if, var(:cond, :bool), then_expr, lit(1), :u64}
      assert {:error, %{message: msg}} = Safety.check(ast)
      assert msg =~ "division by zero"
    end
  end
end
