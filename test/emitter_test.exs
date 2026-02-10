defmodule VaistoBpf.EmitterTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Emitter

  describe "literal emission" do
    test "integer literal" do
      {:ok, ir} = Emitter.emit({:lit, :int, 42})
      assert [{:mov_imm, _reg, 42}] = ir
    end

    test "boolean true" do
      {:ok, ir} = Emitter.emit({:lit, :bool, true})
      assert [{:mov_imm, _reg, 1}] = ir
    end

    test "boolean false" do
      {:ok, ir} = Emitter.emit({:lit, :bool, false})
      assert [{:mov_imm, _reg, 0}] = ir
    end
  end

  describe "arithmetic emission" do
    test "addition with immediate" do
      ast = {:call, :+, [{:var, :x, :u64}, {:lit, :int, 5}], :u64}
      ctx_ast = wrap_in_fn(:add_five, [:x], ast, [:u64], :u64)
      {:ok, ir} = Emitter.emit(ctx_ast)

      assert Enum.any?(ir, &match?({:alu64_imm, :add, _, 5}, &1))
    end

    test "addition with two variables" do
      ast = {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64}
      ctx_ast = wrap_in_fn(:add, [:x, :y], ast, [:u64, :u64], :u64)
      {:ok, ir} = Emitter.emit(ctx_ast)

      assert Enum.any?(ir, &match?({:alu64_reg, :add, _, _}, &1))
    end

    test "subtraction" do
      ast = {:call, :-, [{:var, :x, :u32}, {:lit, :int, 1}], :u32}
      ctx_ast = wrap_in_fn(:dec, [:x], ast, [:u32], :u32)
      {:ok, ir} = Emitter.emit(ctx_ast)

      # u32 → 32-bit ALU
      assert Enum.any?(ir, &match?({:alu32_imm, :sub, _, 1}, &1))
    end

    test "multiplication" do
      ast = {:call, :*, [{:var, :x, :u64}, {:var, :y, :u64}], :u64}
      ctx_ast = wrap_in_fn(:mul, [:x, :y], ast, [:u64, :u64], :u64)
      {:ok, ir} = Emitter.emit(ctx_ast)

      assert Enum.any?(ir, &match?({:alu64_reg, :mul, _, _}, &1))
    end
  end

  describe "comparison emission" do
    test "equality produces conditional jump" do
      ast = {:call, :==, [{:var, :x, :u64}, {:var, :y, :u64}], :bool}
      ctx_ast = wrap_in_fn(:eq, [:x, :y], ast, [:u64, :u64], :bool)
      {:ok, ir} = Emitter.emit(ctx_ast)

      assert Enum.any?(ir, &match?({:jmp_reg, :jeq, _, _, _}, &1))
    end

    test "greater-than" do
      ast = {:call, :>, [{:var, :x, :u64}, {:lit, :int, 0}], :bool}
      ctx_ast = wrap_in_fn(:positive, [:x], ast, [:u64], :bool)
      {:ok, ir} = Emitter.emit(ctx_ast)

      assert Enum.any?(ir, &match?({:jmp_reg, :jgt, _, _, _}, &1))
    end
  end

  describe "if expression" do
    test "emits conditional jump and labels" do
      ast =
        {:if, {:var, :cond, :bool},
         {:lit, :int, 1}, {:lit, :int, 0}, :u64}

      ctx_ast = wrap_in_fn(:choose, [:cond], ast, [:bool], :u64)
      {:ok, ir} = Emitter.emit(ctx_ast)

      # Should have: jmp_imm (condition check), labels, mov_imm for branches
      assert Enum.any?(ir, &match?({:jmp_imm, :jeq, _, 0, _}, &1))
      assert Enum.count(ir, &match?({:label, _}, &1)) >= 3  # fn label + 2 branch labels
      assert Enum.any?(ir, &match?({:ja, _}, &1))
    end
  end

  describe "let bindings" do
    test "binds variable and uses it" do
      ast =
        {:let, [{{:var, :y, :u64}, {:lit, :int, 10}}],
         {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64}, :u64}

      ctx_ast = wrap_in_fn(:with_let, [:x], ast, [:u64], :u64)
      {:ok, ir} = Emitter.emit(ctx_ast)

      # Should load 10 into a register and use it in addition
      assert Enum.any?(ir, &match?({:mov_imm, _, 10}, &1))
      assert Enum.any?(ir, &match?({:alu64_reg, :add, _, _}, &1))
    end
  end

  describe "function definition" do
    test "emits function label and exit" do
      ast =
        {:defn, :identity, [:x],
         {:var, :x, :u64},
         {:fn, [:u64], :u64}}

      {:ok, ir} = Emitter.emit(ast)

      assert {:label, {:fn, :identity}} in ir
      assert :exit in ir
    end

    test "return value is moved to r0" do
      ast =
        {:defn, :const, [],
         {:lit, :int, 42},
         {:fn, [], :u64}}

      {:ok, ir} = Emitter.emit(ast)

      # Result should be moved to r0
      assert Enum.any?(ir, fn
        {:mov_reg, 0, _src} -> true
        _ -> false
      end)
    end

    test "simple add function" do
      ast =
        {:defn, :add, [:x, :y],
         {:call, :+, [{:var, :x, :u64}, {:var, :y, :u64}], :u64},
         {:fn, [:u64, :u64], :u64}}

      {:ok, ir} = Emitter.emit(ast)

      assert {:label, {:fn, :add}} in ir
      assert Enum.any?(ir, &match?({:alu64_reg, :add, _, _}, &1))
      assert :exit in ir
    end
  end

  describe "match expression" do
    test "emits pattern checks and branches" do
      ast =
        {:match, {:var, :x, :u32},
         [
           {{:lit, :int, 0}, {:lit, :int, 100}, :u32},
           {{:var, :_, :u32}, {:lit, :int, 0}, :u32}
         ], :u32}

      ctx_ast = wrap_in_fn(:classify, [:x], ast, [:u32], :u32)
      {:ok, ir} = Emitter.emit(ctx_ast)

      # Should have pattern checks and jumps
      assert Enum.any?(ir, &match?({:jmp_imm, :jne, _, 0, _}, &1))
      assert Enum.any?(ir, &match?({:mov_imm, _, 100}, &1))
    end
  end

  describe "module" do
    test "emits all functions" do
      ast =
        {:module, [
          {:ns, :TestMod},
          {:defn, :f, [:x],
           {:var, :x, :u64},
           {:fn, [:u64], :u64}},
          {:defn, :g, [:y],
           {:lit, :int, 0},
           {:fn, [:u32], :u32}}
        ]}

      {:ok, ir} = Emitter.emit(ast)

      assert {:label, {:fn, :f}} in ir
      assert {:label, {:fn, :g}} in ir
      assert Enum.count(ir, &(&1 == :exit)) == 2
    end
  end

  # Helper: wrap a body expression in a function definition
  defp wrap_in_fn(name, params, body, arg_types, ret_type) do
    {:defn, name, params, body, {:fn, arg_types, ret_type}}
  end
end
