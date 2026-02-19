defmodule VaistoBpf.Loader.Protocol do
  @moduledoc """
  Binary protocol for communicating with the bpf_loader C port.

  Encoding: command byte + little-endian data integers.
  Framing: {:packet, 2} (handled by Erlang port).
  """

  @cmd_load_xdp 0x01
  @cmd_detach 0x02

  @resp_ok 0x00
  @resp_error 0x01

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

  @spec decode_response(:load_xdp | :detach, binary()) ::
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

  def decode_response(_cmd, <<@resp_error, message::binary>>) do
    {:error, message}
  end

  def decode_response(_cmd, data) do
    {:error, "unexpected response: #{inspect(data, limit: 50)}"}
  end

  # -- Private --

  defp decode_map_names(_rest, 0, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_map_names(<<name_len::8, name::binary-size(name_len), rest::binary>>, n, acc)
       when n > 0 do
    decode_map_names(rest, n - 1, [name | acc])
  end

  defp decode_map_names(_rest, _n, _acc), do: {:error, "malformed map names in response"}
end
