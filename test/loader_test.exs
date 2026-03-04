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

  describe "encode_map_lookup/3" do
    test "encodes command, handle, map name, key" do
      result = Protocol.encode_map_lookup(5, "mymap", <<1, 0, 0, 0>>)

      assert <<0x03, 5, 0, 0, 0, 5, "mymap", 4, 0, 0, 0, 1, 0, 0, 0>> = result
    end

    test "handles single-byte key" do
      result = Protocol.encode_map_lookup(0, "m", <<42>>)
      assert <<0x03, 0, 0, 0, 0, 1, "m", 1, 0, 0, 0, 42>> = result
    end
  end

  describe "encode_map_update/5" do
    test "encodes command, handle, map name, key, value, default flags" do
      result = Protocol.encode_map_update(1, "cnt", <<0, 0, 0, 0>>, <<7, 0, 0, 0>>)

      assert <<0x04, 1, 0, 0, 0, 3, "cnt",
               4, 0, 0, 0, 0, 0, 0, 0,
               4, 0, 0, 0, 7, 0, 0, 0,
               0, 0, 0, 0>> = result
    end

    test "encodes with explicit flags" do
      result = Protocol.encode_map_update(0, "m", <<1>>, <<2>>, 1)

      assert <<0x04, 0, 0, 0, 0, 1, "m",
               1, 0, 0, 0, 1,
               1, 0, 0, 0, 2,
               1, 0, 0, 0>> = result
    end
  end

  describe "encode_map_delete/3" do
    test "encodes command, handle, map name, key" do
      result = Protocol.encode_map_delete(2, "tbl", <<10, 0, 0, 0>>)

      assert <<0x05, 2, 0, 0, 0, 3, "tbl", 4, 0, 0, 0, 10, 0, 0, 0>> = result
    end
  end

  describe "decode_response/2 for :map_lookup" do
    test "decodes found value" do
      data = <<0x00, 4, 0, 0, 0, 42, 0, 0, 0>>
      assert {:ok, <<42, 0, 0, 0>>} = Protocol.decode_response(:map_lookup, data)
    end

    test "decodes not found" do
      assert {:ok, nil} = Protocol.decode_response(:map_lookup, <<0x02>>)
    end

    test "decodes error" do
      assert {:error, "map_lookup: map not found"} =
               Protocol.decode_response(:map_lookup, <<0x01, "map_lookup: map not found">>)
    end
  end

  describe "decode_response/2 for :map_update" do
    test "decodes ok" do
      assert :ok = Protocol.decode_response(:map_update, <<0x00>>)
    end

    test "decodes error" do
      assert {:error, "map_update: " <> _} =
               Protocol.decode_response(:map_update, <<0x01, "map_update: failed">>)
    end
  end

  describe "decode_response/2 for :map_delete" do
    test "decodes ok" do
      assert :ok = Protocol.decode_response(:map_delete, <<0x00>>)
    end

    test "decodes not found as ok (idempotent)" do
      assert :ok = Protocol.decode_response(:map_delete, <<0x02>>)
    end

    test "decodes error" do
      assert {:error, "map_delete: " <> _} =
               Protocol.decode_response(:map_delete, <<0x01, "map_delete: failed">>)
    end
  end

  describe "encode_subscribe_ringbuf/2" do
    test "encodes command byte, handle LE, name_len, name" do
      result = Protocol.encode_subscribe_ringbuf(3, "events")
      assert <<0x06, 3, 0, 0, 0, 6, "events">> = result
    end

    test "handles single-char name" do
      result = Protocol.encode_subscribe_ringbuf(0, "e")
      assert <<0x06, 0, 0, 0, 0, 1, "e">> = result
    end

    test "handles large handle" do
      result = Protocol.encode_subscribe_ringbuf(256, "rb")
      assert <<0x06, 0, 1, 0, 0, 2, "rb">> = result
    end
  end

  describe "encode_unsubscribe_ringbuf/2" do
    test "encodes command byte, handle LE, name_len, name" do
      result = Protocol.encode_unsubscribe_ringbuf(1, "events")
      assert <<0x07, 1, 0, 0, 0, 6, "events">> = result
    end

    test "handles zero handle" do
      result = Protocol.encode_unsubscribe_ringbuf(0, "rb")
      assert <<0x07, 0, 0, 0, 0, 2, "rb">> = result
    end
  end

  describe "decode_response/2 for :subscribe_ringbuf" do
    test "decodes ok" do
      assert :ok = Protocol.decode_response(:subscribe_ringbuf, <<0x00>>)
    end

    test "decodes error" do
      assert {:error, "subscribe_ringbuf: map not found"} =
               Protocol.decode_response(:subscribe_ringbuf, <<0x01, "subscribe_ringbuf: map not found">>)
    end
  end

  describe "decode_response/2 for :unsubscribe_ringbuf" do
    test "decodes ok" do
      assert :ok = Protocol.decode_response(:unsubscribe_ringbuf, <<0x00>>)
    end

    test "decodes error" do
      assert {:error, "unsubscribe_ringbuf: subscription not found"} =
               Protocol.decode_response(
                 :unsubscribe_ringbuf,
                 <<0x01, "unsubscribe_ringbuf: subscription not found">>
               )
    end
  end

  describe "decode_event/1" do
    test "decodes ring buffer event with data" do
      # handle=5, name="events", data=<<1,2,3,4>>
      event =
        <<0x10, 5, 0, 0, 0, 6, "events", 4, 0, 0, 0, 1, 2, 3, 4>>

      assert {:ringbuf_event, 5, "events", <<1, 2, 3, 4>>} = Protocol.decode_event(event)
    end

    test "decodes event with empty data" do
      event = <<0x10, 0, 0, 0, 0, 2, "rb", 0, 0, 0, 0>>
      assert {:ringbuf_event, 0, "rb", <<>>} = Protocol.decode_event(event)
    end

    test "decodes event with large handle" do
      event = <<0x10, 0xFF, 0, 0, 0, 1, "x", 1, 0, 0, 0, 42>>
      assert {:ringbuf_event, 255, "x", <<42>>} = Protocol.decode_event(event)
    end

    test "returns :unknown for non-event data" do
      assert :unknown = Protocol.decode_event(<<0xFF>>)
    end

    test "returns :unknown for truncated event" do
      assert :unknown = Protocol.decode_event(<<0x10, 0, 0>>)
    end

    test "returns :unknown for empty binary" do
      assert :unknown = Protocol.decode_event(<<>>)
    end
  end

  describe "decode_response/2 edge cases" do
    test "unexpected data returns error" do
      assert {:error, "unexpected response: " <> _} =
               Protocol.decode_response(:load_xdp, <<0xFF, 0, 0>>)
    end
  end

  # -- Stream B: Generic load protocol --

  describe "prog_type_byte/1" do
    test "maps known types to byte values" do
      assert 0 = Protocol.prog_type_byte(:auto)
      assert 1 = Protocol.prog_type_byte(:xdp)
      assert 2 = Protocol.prog_type_byte(:kprobe)
      assert 3 = Protocol.prog_type_byte(:kretprobe)
      assert 4 = Protocol.prog_type_byte(:tracepoint)
      assert 5 = Protocol.prog_type_byte(:raw_tracepoint)
      assert 6 = Protocol.prog_type_byte(:tc)
      assert 7 = Protocol.prog_type_byte(:socket_filter)
      assert 8 = Protocol.prog_type_byte(:cgroup_skb)
      assert 9 = Protocol.prog_type_byte(:uprobe)
      assert 10 = Protocol.prog_type_byte(:uretprobe)
    end

    test "maps new program types 11-18 to byte values" do
      assert 11 = Protocol.prog_type_byte(:perf_event)
      assert 12 = Protocol.prog_type_byte(:lsm)
      assert 13 = Protocol.prog_type_byte(:sk_msg)
      assert 14 = Protocol.prog_type_byte(:sk_skb)
      assert 15 = Protocol.prog_type_byte(:cgroup_sock)
      assert 16 = Protocol.prog_type_byte(:cgroup_sock_addr)
      assert 17 = Protocol.prog_type_byte(:flow_dissector)
      assert 18 = Protocol.prog_type_byte(:struct_ops)
    end
  end

  describe "prog_types/0" do
    test "returns all supported program types" do
      types = Protocol.prog_types()
      assert :xdp in types
      assert :kprobe in types
      assert :tracepoint in types
      assert length(types) == 19
    end
  end

  describe "encode_load/3" do
    test "encodes XDP load command" do
      elf = <<0x7F, "ELF">>
      result = Protocol.encode_load(elf, :xdp, "eth0")

      # cmd=0x09, elf_size=4 LE, elf data, prog_type=1, target_len=4, "eth0"
      assert <<0x09, 4, 0, 0, 0, 0x7F, "ELF", 1, 4, "eth0">> = result
    end

    test "encodes kprobe load command" do
      elf = <<1, 2, 3>>
      result = Protocol.encode_load(elf, :kprobe, "do_sys_open")

      assert <<0x09, 3, 0, 0, 0, 1, 2, 3, 2, 11, "do_sys_open">> = result
    end

    test "encodes tracepoint load command" do
      elf = <<>>
      target = "syscalls/sys_enter_openat"
      result = Protocol.encode_load(elf, :tracepoint, target)

      target_len = byte_size(target)
      assert <<0x09, 0, 0, 0, 0, 4, ^target_len, ^target::binary>> = result
    end

    test "encodes auto type with empty target" do
      elf = <<"x">>
      result = Protocol.encode_load(elf, :auto, "")

      assert <<0x09, 1, 0, 0, 0, "x", 0, 0>> = result
    end
  end

  describe "encode_load/3 for new program types" do
    test "encodes cgroup_skb with cgroup path target" do
      elf = <<0x7F, "ELF">>
      result = Protocol.encode_load(elf, :cgroup_skb, "/sys/fs/cgroup")
      assert <<0x09, 4, 0, 0, 0, 0x7F, "ELF", 8, 14, "/sys/fs/cgroup">> = result
    end

    test "encodes lsm with empty target" do
      elf = <<1>>
      result = Protocol.encode_load(elf, :lsm, "")
      assert <<0x09, 1, 0, 0, 0, 1, 12, 0>> = result
    end

    test "encodes perf_event with type:config target" do
      elf = <<>>
      result = Protocol.encode_load(elf, :perf_event, "1:1")
      assert <<0x09, 0, 0, 0, 0, 11, 3, "1:1">> = result
    end

    test "encodes tc with interface target" do
      elf = <<0x7F>>
      result = Protocol.encode_load(elf, :tc, "eth0")
      assert <<0x09, 1, 0, 0, 0, 0x7F, 6, 4, "eth0">> = result
    end

    test "encodes struct_ops with empty target" do
      elf = <<>>
      result = Protocol.encode_load(elf, :struct_ops, "")
      assert <<0x09, 0, 0, 0, 0, 18, 0>> = result
    end

    test "encodes socket_filter with empty target" do
      elf = <<>>
      result = Protocol.encode_load(elf, :socket_filter, "")
      assert <<0x09, 0, 0, 0, 0, 7, 0>> = result
    end

    test "encodes cgroup_sock with cgroup path" do
      elf = <<>>
      result = Protocol.encode_load(elf, :cgroup_sock, "/sys/fs/cgroup")
      assert <<0x09, 0, 0, 0, 0, 15, 14, "/sys/fs/cgroup">> = result
    end

    test "encodes cgroup_sock_addr with cgroup path" do
      elf = <<>>
      result = Protocol.encode_load(elf, :cgroup_sock_addr, "/sys/fs/cgroup")
      assert <<0x09, 0, 0, 0, 0, 16, 14, "/sys/fs/cgroup">> = result
    end
  end

  describe "decode_response/2 for :load" do
    test "decodes OK with handle and no maps" do
      data = <<0x00, 7, 0, 0, 0, 0>>
      assert {:ok, %{handle: 7, map_names: []}} = Protocol.decode_response(:load, data)
    end

    test "decodes OK with handle and maps" do
      data = <<0x00, 0, 0, 0, 0, 2, 4, "pkts", 5, "bytes">>

      assert {:ok, %{handle: 0, map_names: ["pkts", "bytes"]}} =
               Protocol.decode_response(:load, data)
    end

    test "decodes error response" do
      data = <<0x01, "load: attach failed">>
      assert {:error, "load: attach failed"} = Protocol.decode_response(:load, data)
    end
  end
end
