defmodule VaistoBpf.ContextTypes do
  @moduledoc """
  Built-in BPF context struct definitions.

  Maps program types to their context struct field lists. These are the
  "virtual" flat structs that BPF programs see — the verifier rewrites
  field accesses to real kernel struct offsets internally.

  Field format matches `deftype {:product, fields}` so existing record
  machinery (Layout, field access, LDX_MEM) works unchanged.
  """

  @context_types %{
    XdpMd: [
      data: :u32, data_end: :u32, data_meta: :u32,
      ingress_ifindex: :u32, rx_queue_index: :u32, egress_ifindex: :u32
    ],
    SkBuff: [
      len: :u32, pkt_type: :u32, mark: :u32, queue_mapping: :u32,
      protocol: :u32, vlan_present: :u32, vlan_tci: :u32, vlan_proto: :u32,
      priority: :u32, ingress_ifindex: :u32, ifindex: :u32, tc_index: :u32,
      cb0: :u32, cb1: :u32, cb2: :u32, cb3: :u32, cb4: :u32,
      hash: :u32, tc_classid: :u32, data: :u32, data_end: :u32,
      napi_id: :u32, family: :u32, remote_ip4: :u32, local_ip4: :u32,
      remote_port: :u32, local_port: :u32
    ],
    PtRegs: [
      r15: :u64, r14: :u64, r13: :u64, r12: :u64, rbp: :u64, rbx: :u64,
      r11: :u64, r10: :u64, r9: :u64, r8: :u64, rax: :u64, rcx: :u64,
      rdx: :u64, rsi: :u64, rdi: :u64, orig_rax: :u64, rip: :u64,
      cs: :u64, flags: :u64, rsp: :u64, ss: :u64
    ],
    BpfSock: [
      bound_dev_if: :u32, family: :u32, type: :u32, protocol: :u32,
      mark: :u32, priority: :u32, src_ip4: :u32, src_ip6_0: :u32,
      src_ip6_1: :u32, src_ip6_2: :u32, src_ip6_3: :u32, src_port: :u32,
      dst_ip4: :u32, dst_ip6_0: :u32, dst_ip6_1: :u32, dst_ip6_2: :u32,
      dst_ip6_3: :u32, dst_port: :u32, state: :u32
    ],
    BpfSockAddr: [
      user_family: :u32, user_ip4: :u32, user_ip6_0: :u32, user_ip6_1: :u32,
      user_ip6_2: :u32, user_ip6_3: :u32, user_port: :u32, family: :u32,
      type: :u32, protocol: :u32, msg_src_ip4: :u32, msg_src_ip6_0: :u32,
      msg_src_ip6_1: :u32, msg_src_ip6_2: :u32, msg_src_ip6_3: :u32
    ],
    BpfSkMsg: [
      data: :u64, data_end: :u64, family: :u32, remote_ip4: :u32,
      remote_ip6_0: :u32, remote_ip6_1: :u32, remote_ip6_2: :u32,
      remote_ip6_3: :u32, local_ip4: :u32, local_ip6_0: :u32,
      local_ip6_1: :u32, local_ip6_2: :u32, local_ip6_3: :u32,
      remote_port: :u32, local_port: :u32, size: :u32
    ],
    BpfFlowKeys: [
      nhoff: :u16, thoff: :u16, addr_proto: :u16, n_proto: :u16,
      sport: :u16, dport: :u16, is_frag: :u8, is_first_frag: :u8,
      is_encap: :u8, ip_proto: :u8, ipv4_src: :u32, ipv4_dst: :u32
    ]
  }

  @program_context %{
    xdp: :XdpMd,
    tc: :SkBuff,
    socket_filter: :SkBuff,
    cgroup_skb: :SkBuff,
    kprobe: :PtRegs,
    kretprobe: :PtRegs,
    uprobe: :PtRegs,
    uretprobe: :PtRegs,
    tracepoint: nil,
    raw_tracepoint: nil,
    perf_event: :PtRegs,
    lsm: nil,
    sk_msg: :BpfSkMsg,
    sk_skb: :SkBuff,
    cgroup_sock: :BpfSock,
    cgroup_sock_addr: :BpfSockAddr,
    flow_dissector: :BpfFlowKeys,
    struct_ops: nil
  }

  @doc "Returns all built-in context types as a map of name → field list."
  @spec all() :: %{atom() => keyword(atom())}
  def all, do: @context_types

  @doc "Returns the field list for a built-in context type, or nil."
  @spec fields(atom()) :: keyword(atom()) | nil
  def fields(name), do: Map.get(@context_types, name)

  @doc "Returns the context type name for a program type, or nil."
  @spec context_for_program(atom()) :: atom() | nil
  def context_for_program(prog_type), do: Map.get(@program_context, prog_type)

  @doc "Returns true if the given name is a built-in context type."
  @spec builtin?(atom()) :: boolean()
  def builtin?(name), do: Map.has_key?(@context_types, name)
end
