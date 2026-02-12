defmodule VaistoBpf.Helpers do
  @moduledoc """
  Static registry of BPF helper functions.

  Maps helper names (atoms) to their kernel-defined IDs and type signatures.
  These are the numbered entry points that eBPF programs use to interact
  with the kernel (timers, maps, tracing, etc.).

  See: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
  """

  # {id, arg_types, ret_type}
  @helpers %{
    map_lookup_elem:        {1,  [:u64, :u64], :u64},
    map_update_elem:        {2,  [:u64, :u64, :u64, :u64], :u64},
    map_delete_elem:        {3,  [:u64, :u64], :u64},
    probe_read:             {4,  [:u64, :u64, :u64], :u64},
    ktime_get_ns:           {5,  [], :u64},
    trace_printk:           {6,  [:u64, :u64], :u64},
    get_smp_processor_id:   {8,  [], :u32},
    get_current_pid_tgid:   {14, [], :u64},
    get_current_uid_gid:    {15, [], :u64},
  }

  @doc "Returns the integer helper ID for the given name, or `{:error, msg}`."
  @spec helper_id(atom()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def helper_id(name) when is_atom(name) do
    case Map.fetch(@helpers, name) do
      {:ok, {id, _args, _ret}} -> {:ok, id}
      :error -> {:error, "unknown BPF helper: #{name}"}
    end
  end

  @doc "Returns the integer helper ID, raising on unknown helpers."
  @spec helper_id!(atom()) :: non_neg_integer()
  def helper_id!(name) do
    case helper_id(name) do
      {:ok, id} -> id
      {:error, msg} -> raise msg
    end
  end

  @doc "Returns the function type `{:fn, arg_types, ret_type}` for the given helper."
  @spec helper_type(atom()) :: {:ok, {:fn, [atom()], atom()}} | {:error, String.t()}
  def helper_type(name) when is_atom(name) do
    case Map.fetch(@helpers, name) do
      {:ok, {_id, args, ret}} -> {:ok, {:fn, args, ret}}
      :error -> {:error, "unknown BPF helper: #{name}"}
    end
  end

  @doc "Returns true if the helper name is known."
  @spec known?(atom()) :: boolean()
  def known?(name) when is_atom(name), do: Map.has_key?(@helpers, name)
end
