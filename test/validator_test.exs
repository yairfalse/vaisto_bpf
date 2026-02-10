defmodule VaistoBpf.ValidatorTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Validator

  # ============================================================================
  # Allowed Constructs
  # ============================================================================

  describe "accepts valid BPF constructs" do
    test "integer literal" do
      assert {:ok, _} = Validator.validate({:lit, :int, 42})
    end

    test "boolean literal" do
      assert {:ok, _} = Validator.validate({:lit, :bool, true})
    end

    test "variable with fixed-width type" do
      assert {:ok, _} = Validator.validate({:var, :x, :u64})
    end

    test "arithmetic call" do
      ast = {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64}
      assert {:ok, _} = Validator.validate(ast)
    end

    test "comparison call" do
      ast = {:call, :>, [{:var, :x, :u32}, {:lit, :int, 0}], :bool}
      assert {:ok, _} = Validator.validate(ast)
    end

    test "if expression" do
      ast =
        {:if, {:call, :>, [{:var, :x, :u64}, {:lit, :int, 0}], :bool},
         {:var, :x, :u64}, {:lit, :int, 0}, :u64}

      assert {:ok, _} = Validator.validate(ast)
    end

    test "let binding" do
      ast =
        {:let, [{{:var, :x, :u64}, {:lit, :int, 42}}],
         {:var, :x, :u64}, :u64}

      assert {:ok, _} = Validator.validate(ast)
    end

    test "defn with fixed-width types" do
      ast =
        {:defn, :add, [:x, :y],
         {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64},
         {:fn, [:u64, :u64], :u64}}

      assert {:ok, _} = Validator.validate(ast)
    end

    test "record type definition" do
      ast = {:deftype, :Event, {:product, [{:pid, :u32}, {:count, :u64}]},
             {:record, :Event, [{:pid, :u32}, {:count, :u64}]}}
      assert {:ok, _} = Validator.validate(ast)
    end

    test "field access" do
      ast = {:field_access, {:var, :event, {:record, :Event, [{:pid, :u32}]}}, :pid, :u32}
      assert {:ok, _} = Validator.validate(ast)
    end

    test "do block" do
      ast = {:do, [{:lit, :int, 1}, {:lit, :int, 2}], :u64}
      assert {:ok, _} = Validator.validate(ast)
    end

    test "module with valid forms" do
      ast =
        {:module, [
          {:ns, :MyProbe},
          {:defn, :probe, [:ctx],
           {:lit, :int, 0},
           {:fn, [:u64], :u32}}
        ]}

      assert {:ok, _} = Validator.validate(ast)
    end

    test "match expression" do
      ast =
        {:match, {:var, :x, :u32},
         [
           {{:lit, :int, 0}, {:lit, :int, 1}, :u32},
           {{:var, :_, :u32}, {:lit, :int, 0}, :u32}
         ], :u32}

      assert {:ok, _} = Validator.validate(ast)
    end

    test "extern declaration" do
      ast = {:extern, :erlang, :hd, {:fn, [:u64], :u64}}
      assert {:ok, _} = Validator.validate(ast)
    end
  end

  # ============================================================================
  # Rejected Constructs
  # ============================================================================

  describe "rejects invalid BPF constructs" do
    test "float literal" do
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate({:lit, :float, 3.14})
      assert msg =~ "floating point"
    end

    test "string literal" do
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate({:lit, :string, "hello"})
      assert msg =~ "strings"
    end

    test "standard :int type" do
      ast = {:var, :x, :int}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ ":int"
    end

    test ":float type in function" do
      ast = {:defn, :bad, [:x], {:var, :x, :float}, {:fn, [:float], :float}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "floating point"
    end

    test "anonymous function" do
      ast = {:fn, [:x], {:var, :x, :u64}, {:fn, [:u64], :u64}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "anonymous functions"
    end

    test "higher-order apply" do
      ast = {:apply, {:var, :f, {:fn, [:u64], :u64}}, [{:lit, :int, 1}], :u64}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "higher-order"
    end

    test "dynamic list" do
      ast = {:list, [{:lit, :int, 1}], {:list, :u64}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "dynamic lists"
    end

    test "list cons" do
      ast = {:cons, {:lit, :int, 1}, {:list, [], {:list, :u64}}, {:list, :u64}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "list cons"
    end

    test "process definition" do
      ast = {:process, :counter, {:lit, :int, 0}, [], :unit}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "processes"
    end

    test "supervision tree" do
      ast = {:supervise, :one_for_one, [], :unit}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "supervision"
    end

    test "receive" do
      ast = {:receive, [], :unit}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "receive"
    end

    test "tuple" do
      ast = {:tuple, [{:lit, :int, 1}], {:tuple, [:u64]}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "tuples"
    end

    test "map" do
      ast = {:map, [{{:lit, :atom, :a}, {:lit, :int, 1}}], :any}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "dynamic maps"
    end

    test "sum type definition" do
      ast = {:deftype, :Result, {:sum, [{:Ok, [:u64]}, {:Err, [:u32]}]},
             {:sum, :Result, [{:Ok, [:u64]}, {:Err, [:u32]}]}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "sum types"
    end

    test "list type in function signature" do
      ast = {:defn, :bad, [:xs], {:lit, :int, 0}, {:fn, [{:list, :u64}], :u32}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "list types"
    end

    test "pid type" do
      ast = {:var, :p, {:pid, :counter, [:increment]}}
      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "PID types"
    end

    test "recursion" do
      ast =
        {:defn, :loop, [:x],
         {:call, :loop, [{:var, :x, :u64}], :u64},
         {:fn, [:u64], :u64}}

      assert {:error, %Vaisto.Error{message: msg}} = Validator.validate(ast)
      assert msg =~ "recursion"
    end
  end
end
