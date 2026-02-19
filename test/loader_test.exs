defmodule VaistoBpf.LoaderTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Loader.Protocol

  describe "encode_load_xdp/2" do
    test "encodes command byte, elf size LE, elf data, iface len, iface" do
      elf = <<0x7F, "ELF", 0, 0, 0, 0>>
      result = Protocol.encode_load_xdp(elf, "lo")

      # cmd=0x01, elf_size=8 LE, elf data, iface_len=2, "lo"
      assert <<0x01, 8, 0, 0, 0, 0x7F, "ELF", 0, 0, 0, 0, 2, "lo">> = result
    end

    test "handles empty ELF" do
      result = Protocol.encode_load_xdp(<<>>, "eth0")
      assert <<0x01, 0, 0, 0, 0, 4, "eth0">> = result
    end

    test "handles long interface name" do
      iface = "wlp2s0f0"
      result = Protocol.encode_load_xdp(<<"x">>, iface)
      assert <<0x01, 1, 0, 0, 0, "x", 8, "wlp2s0f0">> = result
    end
  end

  describe "encode_detach/1" do
    test "encodes command byte and handle LE" do
      assert <<0x02, 0, 0, 0, 0>> = Protocol.encode_detach(0)
      assert <<0x02, 1, 0, 0, 0>> = Protocol.encode_detach(1)
      assert <<0x02, 0xFF, 0, 0, 0>> = Protocol.encode_detach(255)
    end
  end

  describe "decode_response/2 for :load_xdp" do
    test "decodes OK with handle and no maps" do
      data = <<0x00, 42, 0, 0, 0, 0>>
      assert {:ok, %{handle: 42, map_names: []}} = Protocol.decode_response(:load_xdp, data)
    end

    test "decodes OK with handle and one map" do
      data = <<0x00, 1, 0, 0, 0, 1, 5, "mymap">>
      assert {:ok, %{handle: 1, map_names: ["mymap"]}} = Protocol.decode_response(:load_xdp, data)
    end

    test "decodes OK with multiple maps" do
      data = <<0x00, 0, 0, 0, 0, 3, 3, "foo", 3, "bar", 3, "baz">>

      assert {:ok, %{handle: 0, map_names: ["foo", "bar", "baz"]}} =
               Protocol.decode_response(:load_xdp, data)
    end

    test "decodes error response" do
      data = <<0x01, "something went wrong">>
      assert {:error, "something went wrong"} = Protocol.decode_response(:load_xdp, data)
    end

    test "handles malformed map names" do
      # Says 2 maps but only has data for 1
      data = <<0x00, 0, 0, 0, 0, 2, 3, "foo">>
      assert {:error, "malformed map names in response"} = Protocol.decode_response(:load_xdp, data)
    end
  end

  describe "decode_response/2 for :detach" do
    test "decodes OK" do
      assert :ok = Protocol.decode_response(:detach, <<0x00>>)
    end

    test "decodes error" do
      assert {:error, "bad handle"} = Protocol.decode_response(:detach, <<0x01, "bad handle">>)
    end
  end

  describe "decode_response/2 edge cases" do
    test "unexpected data returns error" do
      assert {:error, "unexpected response: " <> _} =
               Protocol.decode_response(:load_xdp, <<0xFF, 0, 0>>)
    end
  end
end
