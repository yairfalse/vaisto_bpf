defmodule VaistoBpf.Helpers do
  @moduledoc """
  Static registry of BPF helper functions.

  Maps helper names (atoms) to their kernel-defined IDs and type signatures.
  These are the numbered entry points that eBPF programs use to interact
  with the kernel (timers, maps, tracing, etc.).

  See: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
  """

  # {id, arg_types, ret_type, ptr_args}
  # ptr_args: 0-based indices of args that must be passed as stack pointers
  @helpers %{
    # ── Map operations ──────────────────────────────────────────────
    map_lookup_elem:        {1,  [:u64, :u64], {:ptr, :u64},         [1]},
    map_update_elem:        {2,  [:u64, :u64, :u64, :u64], :u64,   [1, 2]},
    map_delete_elem:        {3,  [:u64, :u64], :u64,                [1]},
    map_push_elem:          {87, [:u64, :u64, :u64], :u64,          [1]},
    map_pop_elem:           {88, [:u64, :u64], :u64,                [0]},
    map_peek_elem:          {89, [:u64, :u64], :u64,                [0]},
    map_lookup_and_delete_elem: {110, [:u64, :u64], {:ptr, :u64},   [1]},

    # ── Probe / memory reads ───────────────────────────────────────
    probe_read:             {4,  [:u64, :u64, :u64], :u64,          []},
    probe_read_user:        {112, [:u64, :u64, :u64], :u64,         []},
    probe_read_kernel:      {113, [:u64, :u64, :u64], :u64,         []},
    probe_read_user_str:    {114, [:u64, :u64, :u64], :u64,         []},
    probe_read_kernel_str:  {115, [:u64, :u64, :u64], :u64,         []},
    copy_from_user:         {148, [:u64, :u64, :u64], :u64,         []},

    # ── Time ────────────────────────────────────────────────────────
    ktime_get_ns:           {5,  [], :u64,                           []},
    ktime_get_boot_ns:      {125, [], :u64,                          []},
    ktime_get_coarse_ns:    {160, [], :u64,                          []},
    jiffies64:              {118, [], :u64,                          []},

    # ── Tracing / debugging ─────────────────────────────────────────
    trace_printk:           {6,  [:u64, :u64], :u64,                []},
    get_stack:              {67, [:u64, :u64, :u64, :u64], :u64,    []},
    get_stackid:            {27, [:u64, :u64, :u64], :u64,          []},
    perf_event_output:      {25, [:u64, :u64, :u64, :u64, :u64], :u64, []},
    get_attach_cookie:      {174, [:u64], :u64,                     []},

    # ── System info ─────────────────────────────────────────────────
    get_prandom_u32:        {7,  [], :u32,                           []},
    get_smp_processor_id:   {8,  [], :u32,                           []},
    get_numa_node_id:       {42, [], :u64,                           []},
    get_current_pid_tgid:   {14, [], :u64,                           []},
    get_current_uid_gid:    {15, [], :u64,                           []},
    get_current_comm:       {16, [:u64, :u64], :u64,                []},
    get_cgroup_classid:     {17, [:u64], :u64,                      []},
    get_current_cgroup_id:  {80, [], :u64,                           []},
    get_current_ancestor_cgroup_id: {123, [:u64], :u64,             []},
    get_current_task:       {35, [], :u64,                           []},
    get_ns_current_pid_tgid: {120, [:u64, :u64, :u64, :u64], :u64, []},

    # ── Tail calls ──────────────────────────────────────────────────
    tail_call:              {12,  [:u64, :u64, :u32], :u32,         []},

    # ── Ring buffer ─────────────────────────────────────────────────
    ringbuf_output:         {130, [:u64, :u64, :u64, :u64], :u64,  [1]},
    ringbuf_reserve:        {131, [:u64, :u64, :u64], {:ptr, :u8}, []},
    ringbuf_submit:         {132, [:u64, :u64], :u64,              []},
    ringbuf_discard:        {133, [:u64, :u64], :u64,              []},
    ringbuf_query:          {134, [:u64, :u64], :u64,              []},

    # ── Networking ──────────────────────────────────────────────────
    skb_load_bytes:         {26, [:u64, :u64, :u64, :u64], :u64,   []},
    skb_store_bytes:        {9,  [:u64, :u64, :u64, :u64, :u64], :u64, []},
    l3_csum_replace:        {10, [:u64, :u64, :u64, :u64, :u64], :u64, []},
    l4_csum_replace:        {11, [:u64, :u64, :u64, :u64, :u64], :u64, []},
    redirect:               {23, [:u64, :u64], :u64,                []},
    redirect_map:           {51, [:u64, :u64, :u64], :u64,         []},
    clone_redirect:         {13, [:u64, :u64, :u64], :u64,         []},
    fib_lookup:             {69, [:u64, :u64, :u64, :u64], :u64,   []},
    xdp_adjust_head:        {44, [:u64, :u64], :u64,                []},
    xdp_adjust_tail:        {65, [:u64, :u64], :u64,                []},
    xdp_adjust_meta:        {54, [:u64, :u64], :u64,                []},
    csum_diff:              {28, [:u64, :u64, :u64, :u64, :u64], :u64, []},

    # ── Socket / sk_buff ────────────────────────────────────────────
    skb_get_tunnel_key:     {20, [:u64, :u64, :u64, :u64], :u64,   []},
    skb_set_tunnel_key:     {21, [:u64, :u64, :u64, :u64], :u64,   []},
    skb_change_type:        {32, [:u64, :u64], :u64,                []},
    sk_lookup_tcp:          {84, [:u64, :u64, :u64, :u64, :u64], {:ptr, :u64}, []},
    sk_lookup_udp:          {85, [:u64, :u64, :u64, :u64, :u64], {:ptr, :u64}, []},
    sk_release:             {86, [:u64], :u64,                      []},

    # ── Spin lock ───────────────────────────────────────────────────
    spin_lock:              {93, [:u64], :u64,                       []},
    spin_unlock:            {94, [:u64], :u64,                       []},
  }

  @doc "Returns the integer helper ID for the given name, or `{:error, msg}`."
  @spec helper_id(atom()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def helper_id(name) when is_atom(name) do
    case Map.fetch(@helpers, name) do
      {:ok, {id, _args, _ret, _ptr_args}} -> {:ok, id}
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
      {:ok, {_id, args, ret, _ptr_args}} -> {:ok, {:fn, args, ret}}
      :error -> {:error, "unknown BPF helper: #{name}"}
    end
  end

  @doc "Returns the list of 0-based arg indices that must be passed as stack pointers."
  @spec ptr_args(atom()) :: [non_neg_integer()]
  def ptr_args(name) when is_atom(name) do
    case Map.fetch(@helpers, name) do
      {:ok, {_id, _args, _ret, ptr_args}} -> ptr_args
      :error -> []
    end
  end

  @doc "Returns true if the helper name is known."
  @spec known?(atom()) :: boolean()
  def known?(name) when is_atom(name), do: Map.has_key?(@helpers, name)
end
