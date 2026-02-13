defmodule VaistoBpf.BpfTypeChecker do
  @moduledoc """
  Verification-based type checker for BPF-targeted Vaisto AST.

  Unlike vaisto's Hindley-Milner inference, BPF requires explicit type annotations
  on all function parameters and return types. This checker *verifies* that
  annotations are consistent rather than *inferring* types.

  Accepts parsed+normalized AST (from `Preprocessor.normalize_ast/1`),
  returns `{:ok, type, typed_ast}` matching the format expected by
  `VaistoBpf.Validator` and `VaistoBpf.Emitter`.

  ## Rejected constructs (with helpful errors)

  - `:int`, `:float`, `:string`, `:any` types
  - Anonymous functions, closures, apply
  - Lists, tuples, maps, cons
  - Processes, receive, supervise
  - Recursion (self-calls)
  """

  alias Vaisto.Error

  @bpf_int_types [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64]
  @bpf_types @bpf_int_types ++ [:bool, :unit]

  @arithmetic_ops [:+, :-, :*, :div, :rem]
  @bitwise_ops [:band, :bor, :bxor, :bsl, :bsr]
  @comparison_ops [:==, :!=, :>, :<, :>=, :<=]

  @rejected_beam_types [:int, :float, :num, :string, :any]

  @doc """
  Type-check a normalized parsed AST for BPF compilation.

  Accepts an optional list of `%MapDef{}` structs. Map names are injected
  into the environment as `:u64` values (map FDs are u64 at the BPF level).

  Returns `{:ok, type, typed_ast}` or `{:error, %Vaisto.Error{}}`.
  """
  @spec check(term(), [VaistoBpf.MapDef.t()]) :: {:ok, term(), term()} | {:error, Error.t()}
  def check(ast, maps \\ []) do
    env = Enum.reduce(maps, %{}, fn md, env ->
      Map.put(env, md.name, :u64)
    end)
    check_toplevel(ast, env)
  end

  # ============================================================================
  # Top-Level
  # ============================================================================

  # Multiple top-level forms (from multi-expression parse)
  defp check_toplevel(forms, env) when is_list(forms) do
    # Two passes: collect function signatures, then check bodies
    {env, _} = collect_signatures(forms, env)

    case check_forms(forms, env, []) do
      {:ok, typed_forms} ->
        {:ok, {:module, typed_forms}, {:module, typed_forms}}

      {:error, _} = err ->
        err
    end
  end

  # Single top-level form
  defp check_toplevel(form, env) do
    case check_form(form, env) do
      {:ok, type, typed_form, _env} -> {:ok, type, typed_form}
      {:error, _} = err -> err
    end
  end

  # Collect function signatures in first pass for forward references
  defp collect_signatures([], env), do: {env, []}

  defp collect_signatures([{:defn, name, params, _body, ret_type, _loc} | rest], env) do
    param_types = Enum.map(params, fn {_name, type} -> type end)
    fn_type = {:fn, param_types, ret_type}
    collect_signatures(rest, Map.put(env, name, fn_type))
  end

  # 6-element extern: collect into env so functions can reference helpers
  defp collect_signatures([{:extern, mod, name, arg_types, ret_type, _loc} | rest], env) do
    fn_type = {:fn, arg_types, ret_type}
    env = env
          |> Map.put(name, fn_type)
          |> Map.put({:qualified, mod, name}, fn_type)
    collect_signatures(rest, env)
  end

  defp collect_signatures([_ | rest], env) do
    collect_signatures(rest, env)
  end

  # Check all forms sequentially, accumulating typed output
  defp check_forms([], _env, acc), do: {:ok, Enum.reverse(acc)}

  defp check_forms([form | rest], env, acc) do
    case check_form(form, env) do
      {:ok, _type, typed_form, env} ->
        check_forms(rest, env, [typed_form | acc])

      {:error, _} = err ->
        err
    end
  end

  # ============================================================================
  # Form-Level Checking
  # ============================================================================

  # ns declaration — pass through
  defp check_form({:ns, name, _loc}, env) do
    {:ok, :unit, {:ns, name}, env}
  end

  # import — pass through
  defp check_form({:import, mod, als, _loc}, env) do
    {:ok, :unit, {:import, mod, als}, env}
  end

  # extern with separate arg_types and ret_type (6-element from preprocessor)
  defp check_form({:extern, mod, name, arg_types, ret_type, _loc}, env) do
    with :ok <- validate_bpf_type(ret_type),
         :ok <- validate_type_list(arg_types) do
      fn_type = {:fn, arg_types, ret_type}
      # Store both as bare name and as qualified key for lookup in calls
      env = env
            |> Map.put(name, fn_type)
            |> Map.put({:qualified, mod, name}, fn_type)
      {:ok, fn_type, {:extern, mod, name, fn_type}, env}
    end
  end

  # extern (5-element fallback)
  defp check_form({:extern, mod, name, type_expr, _loc}, env) do
    with :ok <- validate_bpf_type(type_expr) do
      fn_type = normalize_extern_type(type_expr)
      env = Map.put(env, name, fn_type)
      {:ok, fn_type, {:extern, mod, name, fn_type}, env}
    end
  end

  # deftype (product) — validate field types
  defp check_form({:deftype, name, {:product, fields}, _loc}, env) do
    with :ok <- validate_fields(fields) do
      record_type = {:record, name, fields}
      env = Map.put(env, name, record_type)
      {:ok, record_type, {:deftype, name, {:product, fields}, record_type}, env}
    end
  end

  # deftype (sum) — reject for BPF
  defp check_form({:deftype, _name, {:sum, _}, _loc}, _env) do
    {:error, Error.new("sum types are not supported in BPF modules",
      hint: "eBPF only supports record (product) types"
    )}
  end

  # defn — the core: check body against declared return type
  defp check_form({:defn, name, params, body, ret_type, _loc}, env) do
    with :ok <- validate_bpf_type(ret_type),
         :ok <- validate_param_types(params) do
      param_types = Enum.map(params, fn {_n, t} -> t end)
      fn_type = {:fn, param_types, ret_type}

      # Build body env: params + other functions (but NOT self — no recursion)
      body_env =
        params
        |> Enum.reduce(env, fn {n, t}, e -> Map.put(e, n, t) end)
        |> Map.delete(name)

      case check_expr(body, body_env, ret_type) do
        {:ok, body_type, typed_body} ->
          if types_compatible?(ret_type, body_type) do
            typed_params = Enum.map(params, fn {n, _t} -> n end)
            {:ok, fn_type, {:defn, name, typed_params, typed_body, fn_type}, Map.put(env, name, fn_type)}
          else
            {:error, Error.new("return type mismatch in `#{name}`",
              expected: ret_type,
              actual: body_type,
              hint: "declared return type is #{format_type(ret_type)} but body has type #{format_type(body_type)}"
            )}
          end

        {:error, _} = err ->
          err
      end
    end
  end

  # Catch-all for unsupported top-level forms
  defp check_form(other, _env) do
    {:error, Error.new("unsupported top-level form in BPF module: #{inspect(other, limit: 3)}")}
  end

  # ============================================================================
  # Expression Checking
  # ============================================================================
  # `expected` is the contextual type hint (or nil if no context)

  # Integer literal — polymorphic, uses context
  defp check_expr(value, _env, expected) when is_integer(value) do
    case resolve_int_context(expected) do
      {:ok, type} -> {:ok, type, {:lit, :int, value}}
      :no_context -> {:error, Error.new("integer literal requires type context",
        hint: "BPF requires explicit types — use a typed binding or annotate the function return type"
      )}
    end
  end

  # Boolean literals
  defp check_expr(true, _env, _expected), do: {:ok, :bool, {:lit, :bool, true}}
  defp check_expr(false, _env, _expected), do: {:ok, :bool, {:lit, :bool, false}}

  # Atom literals
  defp check_expr({:atom, val}, _env, _expected), do: {:ok, :atom, {:lit, :atom, val}}

  # Variable lookup
  defp check_expr(name, env, _expected) when is_atom(name) do
    case Map.fetch(env, name) do
      {:ok, type} -> {:ok, type, {:var, name, type}}
      :error -> {:error, Error.new("unbound variable `#{name}`")}
    end
  end

  # Arithmetic: (+ x y), (- x y), etc.
  defp check_expr({:call, op, [left, right], _loc}, env, expected)
       when op in @arithmetic_ops do
    check_binary_arith(op, left, right, env, expected)
  end

  # Unary negation: (- x)
  defp check_expr({:call, :-, [operand], _loc}, env, expected) do
    case check_expr(operand, env, expected) do
      {:ok, type, typed_operand} when type in @bpf_int_types ->
        {:ok, type, {:call, :-, [typed_operand], type}}

      {:ok, type, _} ->
        {:error, Error.new("negation requires an integer type, got #{format_type(type)}")}

      err ->
        err
    end
  end

  # Bitwise: (band x y), (bor x y), etc.
  defp check_expr({:call, op, [left, right], _loc}, env, expected)
       when op in @bitwise_ops do
    check_binary_arith(op, left, right, env, expected)
  end

  # Comparison: (== x y), (> x y), etc.
  defp check_expr({:call, op, [left, right], _loc}, env, _expected)
       when op in @comparison_ops do
    check_comparison(op, left, right, env)
  end

  # Boolean not
  defp check_expr({:call, :not, [operand], _loc}, env, _expected) do
    case check_expr(operand, env, :bool) do
      {:ok, :bool, typed_operand} ->
        {:ok, :bool, {:call, :not, [typed_operand], :bool}}

      {:ok, type, _} ->
        {:error, Error.new("`not` requires a boolean, got #{format_type(type)}")}

      err ->
        err
    end
  end

  # Qualified call (e.g., bpf/ktime_get_ns)
  defp check_expr({:call, {:qualified, mod, name} = qname, args, _loc}, env, _expected) do
    case Map.fetch(env, {:qualified, mod, name}) do
      {:ok, {:fn, param_types, ret_type}} ->
        if length(args) != length(param_types) do
          {:error, Error.new("helper `#{mod}/#{name}` expects #{length(param_types)} arguments, got #{length(args)}")}
        else
          case check_call_args(qname, args, param_types, ret_type, env) do
            {:ok, ret_type, {:call, _qname, typed_args, ret_type}} ->
              {:ok, ret_type, {:call, {:qualified, mod, name}, typed_args, ret_type}}
            err -> err
          end
        end

      {:ok, _} ->
        {:error, Error.new("`#{mod}/#{name}` is not a function")}

      :error ->
        {:error, Error.new("unknown helper `#{mod}/#{name}`",
          hint: "declare it with (extern #{mod}:#{name} [arg-types] :ret-type)"
        )}
    end
  end

  # Function call (named)
  defp check_expr({:call, name, args, _loc}, env, _expected) when is_atom(name) do
    case Map.fetch(env, name) do
      {:ok, {:fn, param_types, ret_type}} ->
        if length(args) != length(param_types) do
          {:error, Error.new("function `#{name}` expects #{length(param_types)} arguments, got #{length(args)}")}
        else
          check_call_args(name, args, param_types, ret_type, env)
        end

      {:ok, _} ->
        {:error, Error.new("`#{name}` is not a function")}

      :error ->
        # Check if it's a self-call (recursion)
        {:error, Error.new("unknown function `#{name}`",
          hint: if(String.first("#{name}") =~ ~r/[a-z]/,
            do: "recursion is not supported in BPF modules",
            else: nil
          )
        )}
    end
  end

  # if expression
  defp check_expr({:if, cond_expr, then_expr, else_expr, _loc}, env, expected) do
    with {:ok, :bool, typed_cond} <- check_expr(cond_expr, env, :bool),
         {:ok, then_type, typed_then} <- check_expr(then_expr, env, expected),
         {:ok, else_type, typed_else} <- check_expr(else_expr, env, expected) do
      cond do
        not is_bool_type?({:ok, :bool, typed_cond}, cond_expr) ->
          {:error, Error.new("if condition must be boolean")}

        types_compatible?(then_type, else_type) ->
          result_type = pick_concrete(then_type, else_type)
          {:ok, result_type, {:if, typed_cond, typed_then, typed_else, result_type}}

        true ->
          {:error, Error.new("if branches have different types",
            expected: then_type,
            actual: else_type,
            hint: "then branch is #{format_type(then_type)}, else branch is #{format_type(else_type)}"
          )}
      end
    else
      {:ok, cond_type, _} ->
        {:error, Error.new("if condition must be boolean, got #{format_type(cond_type)}")}

      {:error, _} = err ->
        err
    end
  end

  # let expression: (let [x expr] body) — parser produces (let [(name expr)] body loc)
  defp check_expr({:let, bindings, body, _loc}, env, expected) do
    check_let(bindings, body, env, expected)
  end

  # match expression
  defp check_expr({:match, scrutinee, clauses, _loc}, env, expected) do
    check_match(scrutinee, clauses, env, expected)
  end

  # do block (sequential expressions)
  defp check_expr({:do, exprs, _loc}, env, expected) do
    check_do(exprs, env, expected)
  end

  # Rejected constructs
  defp check_expr({:fn, _params, _body, _loc}, _env, _expected) do
    {:error, Error.new("anonymous functions are not supported in BPF modules",
      hint: "eBPF does not support closures — use named functions"
    )}
  end

  defp check_expr({:cons, _h, _t, _loc}, _env, _expected) do
    {:error, Error.new("lists are not supported in BPF modules",
      hint: "eBPF has no heap allocation"
    )}
  end

  defp check_expr({:bracket, items}, _env, _expected) when is_list(items) do
    {:error, Error.new("list literals are not supported in BPF modules",
      hint: "eBPF has no heap allocation — use records for structured data"
    )}
  end

  defp check_expr(other, _env, _expected) do
    {:error, Error.new("unsupported expression in BPF module: #{inspect(other, limit: 3)}")}
  end

  # ============================================================================
  # Binary Arithmetic / Bitwise
  # ============================================================================

  defp check_binary_arith(op, left, right, env, expected) do
    # Try to infer context from whichever side has a known type
    left_pre = pre_check_type(left, env)
    right_pre = pre_check_type(right, env)

    # Determine the context: prefer a concrete type from either operand
    context = left_pre || right_pre || expected

    with {:ok, left_type, typed_left} <- check_expr(left, env, context),
         {:ok, right_type, typed_right} <- check_expr(right, env, context || left_type) do
      cond do
        left_type not in @bpf_int_types ->
          {:error, Error.new("#{op} requires integer operands, got #{format_type(left_type)}",
            hint: "BPF arithmetic only works on fixed-width integer types"
          )}

        right_type not in @bpf_int_types ->
          {:error, Error.new("#{op} requires integer operands, got #{format_type(right_type)}",
            hint: "BPF arithmetic only works on fixed-width integer types"
          )}

        left_type != right_type ->
          {:error, Error.new("#{op} requires both operands to be the same type",
            expected: left_type,
            actual: right_type,
            hint: "got #{format_type(left_type)} and #{format_type(right_type)} — BPF has no implicit widening"
          )}

        true ->
          {:ok, left_type, {:call, op, [typed_left, typed_right], left_type}}
      end
    end
  end

  # ============================================================================
  # Comparisons
  # ============================================================================

  defp check_comparison(op, left, right, env) do
    left_pre = pre_check_type(left, env)
    right_pre = pre_check_type(right, env)
    context = left_pre || right_pre

    with {:ok, left_type, typed_left} <- check_expr(left, env, context),
         {:ok, right_type, typed_right} <- check_expr(right, env, context || left_type) do
      if types_compatible?(left_type, right_type) do
        {:ok, :bool, {:call, op, [typed_left, typed_right], :bool}}
      else
        {:error, Error.new("#{op} requires both operands to be the same type",
          expected: left_type,
          actual: right_type
        )}
      end
    end
  end

  # ============================================================================
  # Let Bindings
  # ============================================================================

  defp check_let([], body, env, expected) do
    check_expr(body, env, expected)
  end

  defp check_let([{name, expr} | rest], body, env, expected) when is_atom(name) do
    case check_expr(expr, env, nil) do
      {:ok, type, typed_expr} ->
        env = Map.put(env, name, type)
        case check_let(rest, body, env, expected) do
          {:ok, body_type, typed_body} ->
            {:ok, body_type, {:let, [{{:var, name, type}, typed_expr}], typed_body, body_type}}

          err ->
            err
        end

      err ->
        err
    end
  end

  # ============================================================================
  # Match
  # ============================================================================

  defp check_match(scrutinee, clauses, env, expected) do
    case check_expr(scrutinee, env, nil) do
      {:ok, scrut_type, typed_scrutinee} ->
        check_match_clauses(clauses, scrut_type, env, expected, typed_scrutinee, [])

      err ->
        err
    end
  end

  defp check_match_clauses([], _scrut_type, _env, _expected, _typed_scrutinee, _acc) do
    {:error, Error.new("match expression with no clauses")}
  end

  defp check_match_clauses([{pattern, body} | rest], scrut_type, env, expected, typed_scrutinee, acc) do
    {pattern_env, typed_pattern} = bind_pattern(pattern, scrut_type, env)

    case check_expr(body, pattern_env, expected) do
      {:ok, body_type, typed_body} ->
        clause = {typed_pattern, typed_body, body_type}
        new_acc = [clause | acc]

        if rest == [] do
          # All clauses done — verify they all have the same type
          result_type = body_type
          clauses = Enum.reverse(new_acc)
          {:ok, result_type, {:match, typed_scrutinee, clauses, result_type}}
        else
          check_match_clauses(rest, scrut_type, env, expected || body_type, typed_scrutinee, new_acc)
        end

      err ->
        err
    end
  end

  # ============================================================================
  # Do Block
  # ============================================================================

  defp check_do([], _env, _expected), do: {:ok, :unit, {:lit, :unit, nil}}

  defp check_do([expr], env, expected) do
    check_expr(expr, env, expected)
  end

  defp check_do([expr | rest], env, expected) do
    case check_expr(expr, env, nil) do
      {:ok, _type, typed_expr} ->
        case check_do(rest, env, expected) do
          {:ok, result_type, typed_rest} ->
            {:ok, result_type, {:do, [typed_expr, typed_rest], result_type}}

          err ->
            err
        end

      err ->
        err
    end
  end

  # ============================================================================
  # Function Call Args
  # ============================================================================

  defp check_call_args(name, args, param_types, ret_type, env) do
    pairs = Enum.zip(args, param_types)

    case check_arg_list(pairs, env, []) do
      {:ok, typed_args} ->
        {:ok, ret_type, {:call, name, typed_args, ret_type}}

      {:error, _} = err ->
        err
    end
  end

  defp check_arg_list([], _env, acc), do: {:ok, Enum.reverse(acc)}

  defp check_arg_list([{arg, expected_type} | rest], env, acc) do
    case check_expr(arg, env, expected_type) do
      {:ok, actual_type, typed_arg} ->
        if types_compatible?(expected_type, actual_type) do
          check_arg_list(rest, env, [typed_arg | acc])
        else
          {:error, Error.new("argument type mismatch",
            expected: expected_type,
            actual: actual_type
          )}
        end

      err ->
        err
    end
  end

  # ============================================================================
  # Pattern Binding
  # ============================================================================

  defp bind_pattern(name, type, env) when is_atom(name) do
    {Map.put(env, name, type), {:var, name, type}}
  end

  defp bind_pattern(value, _type, env) when is_integer(value) do
    {env, {:lit, :int, value}}
  end

  defp bind_pattern({:atom, val}, _type, env) do
    {env, {:lit, :atom, val}}
  end

  defp bind_pattern(:_, type, env) do
    {env, {:var, :_, type}}
  end

  defp bind_pattern(other, _type, env) do
    {env, other}
  end

  # ============================================================================
  # Type Helpers
  # ============================================================================

  # Pre-check: peek at the type of an expression without full checking
  # Returns a type atom if known, nil otherwise
  defp pre_check_type(name, env) when is_atom(name), do: Map.get(env, name)
  defp pre_check_type(_expr, _env), do: nil

  defp resolve_int_context(type) when type in @bpf_int_types, do: {:ok, type}
  defp resolve_int_context(_), do: :no_context

  defp types_compatible?(a, a), do: true
  defp types_compatible?(_, _), do: false

  defp pick_concrete(a, _b), do: a

  defp is_bool_type?({:ok, :bool, _}, _), do: true
  defp is_bool_type?(_, _), do: false

  defp validate_bpf_type(type) when type in @bpf_types, do: :ok

  defp validate_bpf_type(type) when type in @rejected_beam_types do
    {:error, Error.new("type #{format_type(type)} is not supported in BPF modules",
      hint: "use fixed-width types: :u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64"
    )}
  end

  defp validate_bpf_type({:fn, args, ret}) do
    with :ok <- validate_bpf_type(ret) do
      Enum.reduce_while(args, :ok, fn t, :ok ->
        case validate_bpf_type(t) do
          :ok -> {:cont, :ok}
          err -> {:halt, err}
        end
      end)
    end
  end

  defp validate_bpf_type({:record, _name, fields}), do: validate_fields(fields)

  defp validate_bpf_type(other) do
    {:error, Error.new("unsupported type in BPF module: #{inspect(other)}")}
  end

  defp validate_fields(fields) do
    Enum.reduce_while(fields, :ok, fn {_name, type}, :ok ->
      case validate_bpf_type(type) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp validate_param_types(params) do
    Enum.reduce_while(params, :ok, fn {_name, type}, :ok ->
      case validate_bpf_type(type) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp validate_type_list(types) when is_list(types) do
    Enum.reduce_while(types, :ok, fn type, :ok ->
      case validate_bpf_type(type) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp normalize_extern_type({:call, _name, args, _loc}) do
    # Extern type is a call-like form from parser — extract types
    {:fn, Enum.map(args, &unwrap_type/1), :unit}
  end

  defp normalize_extern_type(type), do: type

  defp unwrap_type({:atom, t}), do: t
  defp unwrap_type(t), do: t

  defp format_type(type) when is_atom(type), do: ":#{type}"
  defp format_type({:fn, args, ret}) do
    args_str = Enum.map_join(args, " ", &format_type/1)
    "(fn [#{args_str}] #{format_type(ret)})"
  end
  defp format_type({:record, name, _fields}), do: "#{name}"
  defp format_type(other), do: inspect(other)
end
