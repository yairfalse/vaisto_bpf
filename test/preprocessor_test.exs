defmodule VaistoBpf.PreprocessorTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Preprocessor

  describe "preprocess_source/1" do
    test "capitalizes all BPF integer types" do
      for type <- ~w(u8 u16 u32 u64 i8 i16 i32 i64) do
        source = "(defn f [x :#{type}] :#{type} x)"
        result = Preprocessor.preprocess_source(source)
        upper = String.upcase(type)
        assert result == "(defn f [x :#{upper}] :#{upper} x)",
          "expected :#{type} → :#{upper}"
      end
    end

    test "preserves non-BPF types" do
      source = "(defn f [x :int y :float] :string x)"
      assert Preprocessor.preprocess_source(source) == source
    end

    test "handles multiple BPF types in one expression" do
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      expected = "(defn add [x :U64 y :U64] :U64 (+ x y))"
      assert Preprocessor.preprocess_source(source) == expected
    end

    test "handles mixed BPF and non-BPF types" do
      source = "(defn f [x :u32 y :bool] :u32 x)"
      expected = "(defn f [x :U32 y :bool] :U32 x)"
      assert Preprocessor.preprocess_source(source) == expected
    end

    test "does not replace inside identifiers" do
      # :u64 as part of a longer word should not match (but our regex uses \b)
      source = "(defn u64_helper [x :u64] :u64 x)"
      result = Preprocessor.preprocess_source(source)
      assert result =~ "u64_helper"
      assert result =~ ":U64"
    end
  end

  describe "normalize_ast/1" do
    test "normalizes capitalized BPF types in defn params and return type" do
      # Simulated parsed AST with capitalized types
      ast = {:defn, :add, [{:x, :U64}, {:y, :U64}], {:call, :+, [:x, :y], nil}, :U64, %Vaisto.Parser.Loc{line: 1, col: 1}}
      result = Preprocessor.normalize_ast(ast)

      {:defn, :add, params, _body, ret_type, _loc} = result
      assert params == [{:x, :u64}, {:y, :u64}]
      assert ret_type == :u64
    end

    test "normalizes {:atom, :U64} wrappers" do
      assert Preprocessor.normalize_ast({:atom, :U64}) == {:atom, :u64}
      assert Preprocessor.normalize_ast({:atom, :I32}) == {:atom, :i32}
    end

    test "preserves non-BPF atoms" do
      assert Preprocessor.normalize_ast({:atom, :bool}) == {:atom, :bool}
      assert Preprocessor.normalize_ast(:int) == :int
    end

    test "normalizes nested call args" do
      ast = {:call, :+, [{:atom, :U64}, {:atom, :U32}], nil}
      result = Preprocessor.normalize_ast(ast)
      {:call, :+, [{:atom, :u64}, {:atom, :u32}], nil} = result
    end

    test "normalizes if expression" do
      ast = {:if, {:atom, :U64}, {:atom, :U32}, {:atom, :I64}, nil}
      {:if, {:atom, :u64}, {:atom, :u32}, {:atom, :i64}, nil} = Preprocessor.normalize_ast(ast)
    end

    test "normalizes let bindings" do
      ast = {:let, [{:x, {:atom, :U64}}], {:atom, :U32}, nil}
      {:let, [{:x, {:atom, :u64}}], {:atom, :u32}, nil} = Preprocessor.normalize_ast(ast)
    end

    test "normalizes lists of forms" do
      forms = [{:atom, :U64}, {:atom, :I32}, :bool]
      result = Preprocessor.normalize_ast(forms)
      assert result == [{:atom, :u64}, {:atom, :i32}, :bool]
    end

    test "all 8 BPF types normalize correctly" do
      for {upper, lower} <- [{:U8, :u8}, {:U16, :u16}, {:U32, :u32}, {:U64, :u64},
                              {:I8, :i8}, {:I16, :i16}, {:I32, :i32}, {:I64, :i64}] do
        assert Preprocessor.normalize_ast(upper) == lower
      end
    end
  end

  describe "round-trip: preprocess → parse → normalize" do
    test "simple defn round-trips correctly" do
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      # Single expression → bare tuple (not a list)
      normalized = Preprocessor.normalize_ast(parsed)

      {:defn, :add, params, _body, :u64, _loc} = normalized
      assert params == [{:x, :u64}, {:y, :u64}]
    end

    test "deftype with BPF fields round-trips" do
      source = "(deftype Point [x :u32 y :u32])"
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      # Parser wraps fields in {:product, fields}
      {:deftype, :Point, {:product, fields}, _loc} = normalized
      assert fields == [{:x, :u32}, {:y, :u32}]
    end

    test "module with ns and multiple defns" do
      source = """
      (ns Math)
      (defn add [x :u64 y :u64] :u64 (+ x y))
      (defn sub [a :i32 b :i32] :i32 (- a b))
      """
      preprocessed = Preprocessor.preprocess_source(source)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      assert length(normalized) == 3
      [{:ns, :Math, _}, {:defn, :add, add_params, _, :u64, _}, {:defn, :sub, sub_params, _, :i32, _}] = normalized
      assert add_params == [{:x, :u64}, {:y, :u64}]
      assert sub_params == [{:a, :i32}, {:b, :i32}]
    end
  end
end
