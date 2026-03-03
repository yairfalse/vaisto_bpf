defmodule VaistoBpf.Loader.Protocol do
  @moduledoc """
  Binary protocol for communicating with the bpf_loader C port.

  Encoding: command byte + little-endian data integers.
  Framing: {:packet, 2} (handled by Erlang port).
  """

  @cmd_load_xdp 0x01
  @cmd_detach 0x02
  @cmd_map_lookup 0x03
  @cmd_map_update 0x04
  @cmd_map_delete 0x05
  @cmd_subscribe_ringbuf 0x06
  @cmd_unsubscribe_ringbuf 0x07
  @cmd_map_get_next_key 0x08
  @cmd_load 0x09

  @resp_ok 0x00
  @resp_error 0x01
  @resp_not_found 0x02
  @resp_ringbuf_event 0x10

  # Program type byte values (must match C side)
  @prog_type_auto 0
  @prog_type_xdp 1
  @prog_type_kprobe 2
  @prog_type_kretprobe 3
  @prog_type_tracepoint 4
  @prog_type_raw_tp 5
  @prog_type_tc 6
  @prog_type_socket_filter 7
  @prog_type_cgroup_skb 8
  @prog_type_uprobe 9
  @prog_type_uretprobe 10
  @prog_type_perf_event 11
  @prog_type_lsm 12
  @prog_type_sk_msg 13
  @prog_type_sk_skb 14
  @prog_type_cgroup_sock 15
  @prog_type_cgroup_sock_addr 16
  @prog_type_flow_dissector 17
  @prog_type_struct_ops 18

  @prog_type_map %{
    auto: @prog_type_auto,
    xdp: @prog_type_xdp,
    kprobe: @prog_type_kprobe,
    kretprobe: @prog_type_kretprobe,
    tracepoint: @prog_type_tracepoint,
    raw_tracepoint: @prog_type_raw_tp,
    tc: @prog_type_tc,
    socket_filter: @prog_type_socket_filter,
    cgroup_skb: @prog_type_cgroup_skb,
    uprobe: @prog_type_uprobe,
    uretprobe: @prog_type_uretprobe,
    perf_event: @prog_type_perf_event,
    lsm: @prog_type_lsm,
    sk_msg: @prog_type_sk_msg,
    sk_skb: @prog_type_sk_skb,
    cgroup_sock: @prog_type_cgroup_sock,
    cgroup_sock_addr: @prog_type_cgroup_sock_addr,
    flow_dissector: @prog_type_flow_dissector,
    struct_ops: @prog_type_struct_ops
  }

  @doc "Returns the list of supported program type atoms."
  @spec prog_types() :: [atom()]
  def prog_types, do: Map.keys(@prog_type_map)

  @doc "Convert a program type atom to its wire byte value."
  @spec prog_type_byte(atom()) :: non_neg_integer()
  def prog_type_byte(type) when is_map_key(@prog_type_map, type), do: @prog_type_map[type]

  @spec encode_load_xdp(binary(), String.t()) :: binary()
  def encode_load_xdp(elf_binary, interface) when is_binary(elf_binary) and is_binary(interface) do
    elf_size = byte_size(elf_binary)
    iface = interface
    iface_len = byte_size(iface)

    <<@cmd_load_xdp::8, elf_size::little-32, elf_binary::binary,
      iface_len::8, iface::binary>>
  end

  @doc """
  Encode a generic load command.

  Format: [0x09][elf_size:4LE][elf:N][prog_type:1][target_len:1][target:N]
  """
  @spec encode_load(binary(), atom(), String.t()) :: binary()
  def encode_load(elf_binary, prog_type, attach_target)
      when is_binary(elf_binary) and is_atom(prog_type) and is_binary(attach_target) do
    elf_size = byte_size(elf_binary)
    type_byte = prog_type_byte(prog_type)
    target_len = byte_size(attach_target)

    <<@cmd_load::8, elf_size::little-32, elf_binary::binary,
      type_byte::8, target_len::8, attach_target::binary>>
  end

  @spec encode_detach(non_neg_integer()) :: binary()
  def encode_detach(handle) when is_integer(handle) and handle >= 0 do
    <<@cmd_detach::8, handle::little-32>>
  end

  @max_map_name_len 255

  @spec encode_map_lookup(non_neg_integer(), String.t(), binary()) :: binary()
  def encode_map_lookup(handle, map_name, key)
      when is_integer(handle) and handle >= 0 and is_binary(map_name) and is_binary(key)
           and byte_size(map_name) <= @max_map_name_len do
    name_len = byte_size(map_name)
    key_len = byte_size(key)

    <<@cmd_map_lookup::8, handle::little-32,
      name_len::8, map_name::binary,
      key_len::little-32, key::binary>>
  end

  @spec encode_map_update(non_neg_integer(), String.t(), binary(), binary(), non_neg_integer()) ::
          binary()
  def encode_map_update(handle, map_name, key, value, flags \\ 0)
      when is_integer(handle) and handle >= 0 and is_binary(map_name) and is_binary(key) and
             is_binary(value) and is_integer(flags) and flags >= 0
             and byte_size(map_name) <= @max_map_name_len do
    name_len = byte_size(map_name)
    key_len = byte_size(key)
    val_len = byte_size(value)

    <<@cmd_map_update::8, handle::little-32,
      name_len::8, map_name::binary,
      key_len::little-32, key::binary,
      val_len::little-32, value::binary,
      flags::little-32>>
  end

  @spec encode_map_delete(non_neg_integer(), String.t(), binary()) :: binary()
  def encode_map_delete(handle, map_name, key)
      when is_integer(handle) and handle >= 0 and is_binary(map_name) and is_binary(key)
           and byte_size(map_name) <= @max_map_name_len do
    name_len = byte_size(map_name)
    key_len = byte_size(key)

    <<@cmd_map_delete::8, handle::little-32,
      name_len::8, map_name::binary,
      key_len::little-32, key::binary>>
  end

  @spec encode_map_get_next_key(non_neg_integer(), String.t(), binary() | nil) :: binary()
  def encode_map_get_next_key(handle, map_name, key \\ nil)
      when is_integer(handle) and handle >= 0 and is_binary(map_name)
           and byte_size(map_name) <= @max_map_name_len do
    name_len = byte_size(map_name)

    case key do
      nil ->
        <<@cmd_map_get_next_key::8, handle::little-32,
          name_len::8, map_name::binary,
          0::little-32>>

      key when is_binary(key) ->
        key_len = byte_size(key)
        <<@cmd_map_get_next_key::8, handle::little-32,
          name_len::8, map_name::binary,
          key_len::little-32, key::binary>>
    end
  end

  @spec encode_subscribe_ringbuf(non_neg_integer(), String.t()) :: binary()
  def encode_subscribe_ringbuf(handle, map_name)
      when is_integer(handle) and handle >= 0 and is_binary(map_name)
           and byte_size(map_name) <= @max_map_name_len do
    name_len = byte_size(map_name)
    <<@cmd_subscribe_ringbuf::8, handle::little-32, name_len::8, map_name::binary>>
  end

  @spec encode_unsubscribe_ringbuf(non_neg_integer(), String.t()) :: binary()
  def encode_unsubscribe_ringbuf(handle, map_name)
      when is_integer(handle) and handle >= 0 and is_binary(map_name)
           and byte_size(map_name) <= @max_map_name_len do
    name_len = byte_size(map_name)
    <<@cmd_unsubscribe_ringbuf::8, handle::little-32, name_len::8, map_name::binary>>
  end

  @spec decode_response(atom(), binary()) ::
          {:ok, map()} | :ok | {:error, String.t()}
  def decode_response(:load, <<@resp_ok, handle::little-32, num_maps::8, rest::binary>>) do
    case decode_map_names(rest, num_maps, []) do
      {:ok, names} -> {:ok, %{handle: handle, map_names: names}}
      {:error, _} = err -> err
    end
  end

  def decode_response(:load_xdp, <<@resp_ok, handle::little-32, num_maps::8, rest::binary>>) do
    case decode_map_names(rest, num_maps, []) do
      {:ok, names} -> {:ok, %{handle: handle, map_names: names}}
      {:error, _} = err -> err
    end
  end

  def decode_response(:detach, <<@resp_ok>>) do
    :ok
  end

  def decode_response(:map_lookup, <<@resp_ok, val_len::little-32, value::binary-size(val_len)>>) do
    {:ok, value}
  end

  def decode_response(:map_lookup, <<@resp_not_found>>) do
    {:ok, nil}
  end

  def decode_response(:map_update, <<@resp_ok>>) do
    :ok
  end

  def decode_response(:map_delete, <<@resp_ok>>) do
    :ok
  end

  def decode_response(:map_delete, <<@resp_not_found>>) do
    :ok
  end

  def decode_response(:map_get_next_key, <<@resp_ok, key_len::little-32, key::binary-size(key_len)>>) do
    {:ok, key}
  end

  def decode_response(:map_get_next_key, <<@resp_not_found>>) do
    {:ok, nil}
  end

  def decode_response(:subscribe_ringbuf, <<@resp_ok>>) do
    :ok
  end

  def decode_response(:unsubscribe_ringbuf, <<@resp_ok>>) do
    :ok
  end

  def decode_response(_cmd, <<@resp_error, message::binary>>) do
    {:error, message}
  end

  def decode_response(_cmd, data) do
    {:error, "unexpected response: #{inspect(data, limit: 50)}"}
  end

  @doc "Decode an unsolicited ring buffer event from the C port."
  @spec decode_event(binary()) :: {:ringbuf_event, non_neg_integer(), String.t(), binary()} | :unknown
  def decode_event(
        <<@resp_ringbuf_event, handle::little-32, name_len::8, name::binary-size(name_len),
          data_len::little-32, data::binary-size(data_len)>>
      ) do
    {:ringbuf_event, handle, name, data}
  end

  def decode_event(_), do: :unknown

  # -- Private --

  defp decode_map_names(_rest, 0, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_map_names(<<name_len::8, name::binary-size(name_len), rest::binary>>, n, acc)
       when n > 0 do
    decode_map_names(rest, n - 1, [name | acc])
  end

  defp decode_map_names(_rest, _n, _acc), do: {:error, "malformed map names in response"}
end
