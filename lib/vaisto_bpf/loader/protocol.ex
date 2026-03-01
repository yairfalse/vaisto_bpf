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

  @resp_ok 0x00
  @resp_error 0x01
  @resp_not_found 0x02
  @resp_ringbuf_event 0x10

  @spec encode_load_xdp(binary(), String.t()) :: binary()
  def encode_load_xdp(elf_binary, interface) when is_binary(elf_binary) and is_binary(interface) do
    elf_size = byte_size(elf_binary)
    iface = interface
    iface_len = byte_size(iface)

    <<@cmd_load_xdp::8, elf_size::little-32, elf_binary::binary,
      iface_len::8, iface::binary>>
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

  @spec decode_response(:load_xdp | :detach | :map_lookup | :map_update | :map_delete | :map_get_next_key, binary()) ::
          {:ok, map()} | :ok | {:error, String.t()}
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
