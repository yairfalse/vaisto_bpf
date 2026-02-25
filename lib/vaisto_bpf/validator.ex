defmodule VaistoBpf.Validator do
  @moduledoc """
  Validates that a typed Vaisto AST is within the eBPF-compilable subset.

  Walks the typed AST and rejects constructs that eBPF cannot support:
  floats, strings, dynamic lists, closures, recursion, processes, and
  standard `:int` (must use fixed-width types like `:u64`).

  Returns `{:ok, ast}` if valid, `{:error, %Vaisto.Error{}}` with a
  helpful message if not.
  """

  alias Vaisto.Error

  @rejected_types [:float, :string, :any]

  @doc """
  Validate a typed AST for BPF compatibility.

  Accepts a single typed AST node or a `{:module, forms}` wrapper.
  """
  @spec validate(term()) :: {:ok, term()} | {:error, Error.t()}
  def validate(ast) do
    case do_validate(ast, %{functions: %{}, depth: 0}) do
      :ok -> {:ok, ast}
      {:error, _} = err -> err
    end
  end

  # ============================================================================
  # Module / Top-Level
  # ============================================================================

  defp do_validate({:module, forms}, ctx) do
    # First pass: collect function names for recursion detection
    fn_names =
      forms
      |> Enum.filter(&match?({:defn, _, _, _, _}, &1))
      |> Enum.map(fn {:defn, name, _, _, _} -> name end)
      |> MapSet.new()

    ctx = %{ctx | functions: fn_names}
    validate_list(forms, ctx)
  end

  # ============================================================================
  # Allowed Constructs
  # ============================================================================

  # Namespace and imports — pass through
  defp do_validate({:ns, _name}, _ctx), do: :ok
  defp do_validate({:import, _mod, _alias}, _ctx), do: :ok

  # Extern declarations — allowed (BPF helpers)
  defp do_validate({:extern, _mod, _name, type}, ctx) do
    validate_type(type, ctx)
  end

  # Type definitions — records only
  defp do_validate({:deftype, _name, {:product, fields}, _type}, ctx) do
    Enum.reduce_while(fields, :ok, fn {_name, type}, :ok ->
      case validate_type(type, ctx) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp do_validate({:deftype, _name, {:sum, _variants}, _type}, _ctx) do
    {:error, Error.new("sum types are not supported in BPF modules",
      hint: "eBPF only supports record (product) types"
    )}
  end

  # Function definition — the core of BPF programs
  defp do_validate({:defn, name, params, body, fn_type}, ctx) do
    with :ok <- validate_type(fn_type, ctx),
         :ok <- validate_params(params, ctx),
         # Check body for recursion — the function's own name is in scope
         :ok <- do_validate(body, %{ctx | depth: ctx.depth + 1}) do
      check_no_self_call(body, name)
    end
  end

  # Multi-clause functions
  defp do_validate({:defn_multi, name, _arity, clauses, fn_type}, ctx) do
    with :ok <- validate_type(fn_type, ctx) do
      Enum.reduce_while(clauses, :ok, fn {_pattern, body, _type}, :ok ->
        case do_validate(body, %{ctx | depth: ctx.depth + 1}) do
          :ok ->
            case check_no_self_call(body, name) do
              :ok -> {:cont, :ok}
              err -> {:halt, err}
            end
          err -> {:halt, err}
        end
      end)
    end
  end

  # Value definitions
  defp do_validate({:defval, _name, expr, _type}, ctx) do
    do_validate(expr, ctx)
  end

  # Literals — integers and booleans only
  defp do_validate({:lit, :int, _val}, _ctx), do: :ok
  defp do_validate({:lit, :bool, _val}, _ctx), do: :ok
  defp do_validate({:lit, :atom, _val}, _ctx), do: :ok
  defp do_validate({:lit, :unit, _val}, _ctx), do: :ok

  defp do_validate({:lit, :float, _val}, _ctx) do
    {:error, Error.new("floating point is not supported in BPF modules",
      hint: "eBPF does not support floating point arithmetic — use integer types"
    )}
  end

  defp do_validate({:lit, :string, _val}, _ctx) do
    {:error, Error.new("strings are not supported in BPF modules",
      hint: "eBPF has no dynamic memory — use fixed-size byte arrays or atom constants"
    )}
  end

  # Variables
  defp do_validate({:var, _name, type}, ctx), do: validate_type(type, ctx)

  # Function references
  defp do_validate({:fn_ref, _name, _arity, _type}, _ctx), do: :ok

  # Arithmetic / calls
  defp do_validate({:call, op, args, ret_type}, ctx) when is_atom(op) do
    with :ok <- validate_type(ret_type, ctx),
         :ok <- validate_list(args, ctx) do
      :ok
    end
  end

  # Qualified calls (e.g., Mod.func)
  defp do_validate({:call, {:qualified, _mod, _func}, args, ret_type}, ctx) do
    with :ok <- validate_type(ret_type, ctx),
         :ok <- validate_list(args, ctx) do
      :ok
    end
  end

  # Apply (higher-order) — reject closures
  defp do_validate({:apply, _func, _args, _type}, _ctx) do
    {:error, Error.new("higher-order function application is not supported in BPF modules",
      hint: "eBPF does not support closures or indirect calls"
    )}
  end

  # Anonymous functions — reject
  defp do_validate({:fn, _params, _body, _type}, _ctx) do
    {:error, Error.new("anonymous functions are not supported in BPF modules",
      hint: "eBPF does not support closures — use named functions"
    )}
  end

  # if/else
  defp do_validate({:if, cond_expr, then_expr, else_expr, _type}, ctx) do
    with :ok <- do_validate(cond_expr, ctx),
         :ok <- do_validate(then_expr, ctx),
         :ok <- do_validate(else_expr, ctx) do
      :ok
    end
  end

  # let bindings
  defp do_validate({:let, bindings, body, _type}, ctx) do
    with :ok <- validate_bindings(bindings, ctx),
         :ok <- do_validate(body, ctx) do
      :ok
    end
  end

  # match expressions
  defp do_validate({:match, expr, clauses, _type}, ctx) do
    with :ok <- do_validate(expr, ctx) do
      Enum.reduce_while(clauses, :ok, fn {_pattern, body, _type}, :ok ->
        case do_validate(body, ctx) do
          :ok -> {:cont, :ok}
          err -> {:halt, err}
        end
      end)
    end
  end

  # for-range loops
  defp do_validate({:for_range, _var, start, end_expr, body, _iter_type}, ctx) do
    with :ok <- do_validate(start, ctx),
         :ok <- do_validate(end_expr, ctx),
         :ok <- do_validate(body, ctx) do
      :ok
    end
  end

  # do blocks (sequential expressions)
  defp do_validate({:do, exprs, _type}, ctx) do
    validate_list(exprs, ctx)
  end

  # Type casts
  defp do_validate({:cast, _target_type, inner, _src_type}, ctx) do
    do_validate(inner, ctx)
  end

  # Field access on records
  defp do_validate({:field_access, expr, _field, _type}, ctx) do
    do_validate(expr, ctx)
  end

  defp do_validate({:field_access, expr, _field, _record_type, _type}, ctx) do
    do_validate(expr, ctx)
  end

  # ============================================================================
  # Rejected Constructs
  # ============================================================================

  # Lists — reject dynamic lists
  defp do_validate({:list, _elems, _type}, _ctx) do
    {:error, Error.new("dynamic lists are not supported in BPF modules",
      hint: "eBPF has no heap allocation — use fixed-size arrays or records"
    )}
  end

  defp do_validate({:cons, _head, _tail, _type}, _ctx) do
    {:error, Error.new("list cons is not supported in BPF modules",
      hint: "eBPF has no heap allocation"
    )}
  end

  # Processes — reject entirely
  defp do_validate({:process, _name, _init, _clauses, _type}, _ctx) do
    {:error, Error.new("processes are not supported in BPF modules",
      hint: "eBPF runs in kernel space — use BEAM processes on the userspace side"
    )}
  end

  defp do_validate({:supervise, _strategy, _children, _type}, _ctx) do
    {:error, Error.new("supervision trees are not supported in BPF modules",
      hint: "eBPF runs in kernel space — use BEAM supervision on the userspace side"
    )}
  end

  defp do_validate({:receive, _clauses, _type}, _ctx) do
    {:error, Error.new("receive is not supported in BPF modules",
      hint: "eBPF cannot receive messages — this is a BEAM construct"
    )}
  end

  # Maps (Elixir-style) — not BPF maps, reject
  defp do_validate({:map, _pairs, _type}, _ctx) do
    {:error, Error.new("dynamic maps are not supported in BPF modules",
      hint: "use BPF map helpers (bpf/map-lookup, bpf/map-update!) for kernel maps"
    )}
  end

  # Tuples — reject (use records)
  defp do_validate({:tuple, _elems, _type}, _ctx) do
    {:error, Error.new("tuples are not supported in BPF modules",
      hint: "use record types instead — they have known layouts for eBPF"
    )}
  end

  # Catch-all for unknown nodes
  defp do_validate(node, _ctx) when is_atom(node), do: :ok
  defp do_validate(node, _ctx) when is_integer(node), do: :ok

  defp do_validate(other, _ctx) do
    {:error, Error.new("unsupported AST node in BPF module: #{inspect(other, limit: 3)}")}
  end

  # ============================================================================
  # Type Validation
  # ============================================================================

  defp validate_type(:int, _ctx) do
    {:error, Error.new("standard :int is not supported in BPF modules",
      hint: "eBPF requires fixed-width types — use :u32, :u64, :i32, :i64, etc."
    )}
  end

  defp validate_type(:float, _ctx) do
    {:error, Error.new("floating point is not supported in BPF modules",
      hint: "eBPF does not support floating point arithmetic"
    )}
  end

  defp validate_type(:string, _ctx) do
    {:error, Error.new("strings are not supported in BPF modules",
      hint: "eBPF has no dynamic memory"
    )}
  end

  defp validate_type(:any, _ctx) do
    {:error, Error.new(":any type is not supported in BPF modules",
      hint: "all types must be concrete and fixed-width for eBPF"
    )}
  end

  # BPF-compatible types
  defp validate_type(t, _ctx)
       when t in [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64, :bool, :unit, :atom] do
    :ok
  end

  defp validate_type({:fn, arg_types, ret_type}, ctx) do
    with :ok <- validate_type(ret_type, ctx) do
      Enum.reduce_while(arg_types, :ok, fn t, :ok ->
        case validate_type(t, ctx) do
          :ok -> {:cont, :ok}
          err -> {:halt, err}
        end
      end)
    end
  end

  defp validate_type({:record, _name, fields}, ctx) do
    Enum.reduce_while(fields, :ok, fn {_name, type}, :ok ->
      case validate_type(type, ctx) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp validate_type({:list, _elem_type}, _ctx) do
    {:error, Error.new("list types are not supported in BPF modules",
      hint: "eBPF has no heap allocation"
    )}
  end

  defp validate_type({:pid, _name, _msgs}, _ctx) do
    {:error, Error.new("PID types are not supported in BPF modules",
      hint: "processes are a BEAM concept"
    )}
  end

  defp validate_type({:tvar, _id}, _ctx), do: :ok
  defp validate_type({:atom, _val}, _ctx), do: :ok

  defp validate_type(other, _ctx) when other in @rejected_types do
    {:error, Error.new("type #{inspect(other)} is not supported in BPF modules")}
  end

  defp validate_type(_other, _ctx), do: :ok

  # ============================================================================
  # Helpers
  # ============================================================================

  defp validate_list(items, ctx) do
    Enum.reduce_while(items, :ok, fn item, :ok ->
      case do_validate(item, ctx) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp validate_params(params, ctx) when is_list(params) do
    Enum.reduce_while(params, :ok, fn
      param, :ok when is_atom(param) -> {:cont, :ok}
      {:var, _name, type}, :ok ->
        case validate_type(type, ctx) do
          :ok -> {:cont, :ok}
          err -> {:halt, err}
        end
      _, :ok -> {:cont, :ok}
    end)
  end

  defp validate_bindings(bindings, ctx) when is_list(bindings) do
    Enum.reduce_while(bindings, :ok, fn
      {_pattern, expr}, :ok ->
        case do_validate(expr, ctx) do
          :ok -> {:cont, :ok}
          err -> {:halt, err}
        end
      _other, :ok -> {:cont, :ok}
    end)
  end

  # Simple recursion check: look for calls to the function's own name in its body
  defp check_no_self_call(ast, fn_name) do
    if contains_call?(ast, fn_name) do
      {:error, Error.new("recursion is not supported in BPF modules",
        hint: "eBPF programs must terminate — the kernel verifier rejects recursive calls",
        note: "function `#{fn_name}` calls itself"
      )}
    else
      :ok
    end
  end

  defp contains_call?({:call, name, _args, _type}, target) when name == target, do: true

  defp contains_call?(tuple, target) when is_tuple(tuple) do
    tuple
    |> Tuple.to_list()
    |> Enum.any?(&contains_call?(&1, target))
  end

  defp contains_call?(list, target) when is_list(list) do
    Enum.any?(list, &contains_call?(&1, target))
  end

  defp contains_call?(_other, _target), do: false
end
