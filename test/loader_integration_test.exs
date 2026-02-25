defmodule VaistoBpf.LoaderIntegrationTest do
  use ExUnit.Case

  @moduletag :linux

  alias VaistoBpf.Loader

  @xdp_pass_source """
  (program :xdp)
  (defn xdp_pass [ctx :XdpMd] :u32 2)
  """

  @xdp_with_map_source """
  (program :xdp)
  (defmap counters :hash :u32 :u32 1024)
  (extern bpf:map_update_elem [:u64 :u32 :u32 :u64] :u64)

  (defn xdp_count [ctx :XdpMd] :u32
    (let [key (. ctx :ingress_ifindex)]
      (do
        (bpf/map_update_elem counters key key 0)
        2)))
  """

  setup do
    {:ok, pid} = Loader.start_link()
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    %{loader: pid}
  end

  describe "load and detach XDP on loopback" do
    test "load XDP_PASS, get handle, detach", %{loader: loader} do
      {:ok, elf} = VaistoBpf.compile_source_to_elf(@xdp_pass_source)
      assert {:ok, handle, map_names} = Loader.load_xdp(loader, elf, "lo")
      assert is_integer(handle) and handle >= 0
      assert is_list(map_names)
      assert :ok = Loader.detach(loader, handle)
    end

    test "load_xdp_source convenience works end-to-end", %{loader: loader} do
      assert {:ok, handle, _maps} = Loader.load_xdp_source(loader, @xdp_pass_source, "lo")
      assert :ok = Loader.detach(loader, handle)
    end
  end

  describe "programs with maps" do
    test "reports map names", %{loader: loader} do
      {:ok, elf} = VaistoBpf.compile_source_to_elf(@xdp_with_map_source)
      assert {:ok, handle, map_names} = Loader.load_xdp(loader, elf, "lo")
      assert "counters" in map_names
      assert :ok = Loader.detach(loader, handle)
    end
  end

  describe "error cases" do
    test "invalid ELF returns error", %{loader: loader} do
      assert {:error, msg} = Loader.load_xdp(loader, "not an elf", "lo")
      assert is_binary(msg)
    end

    test "nonexistent interface returns error", %{loader: loader} do
      {:ok, elf} = VaistoBpf.compile_source_to_elf(@xdp_pass_source)
      assert {:error, msg} = Loader.load_xdp(loader, elf, "definitely_not_a_real_iface99")
      assert msg =~ "interface" or msg =~ "unknown"
    end
  end

  describe "map operations" do
    setup %{loader: loader} do
      {:ok, elf} = VaistoBpf.compile_source_to_elf(@xdp_with_map_source)
      {:ok, handle, map_names} = Loader.load_xdp(loader, elf, "lo")
      assert "counters" in map_names

      on_exit(fn ->
        if Process.alive?(loader), do: catch_exit(Loader.detach(loader, handle))
      end)

      %{handle: handle}
    end

    test "update then lookup returns the value", %{loader: loader, handle: handle} do
      key = <<1, 0, 0, 0>>
      value = <<42, 0, 0, 0>>
      assert :ok = Loader.map_update(loader, handle, "counters", key, value)
      assert {:ok, <<42, 0, 0, 0>>} = Loader.map_lookup(loader, handle, "counters", key)
    end

    test "lookup non-existent key returns nil", %{loader: loader, handle: handle} do
      key = <<99, 0, 0, 0>>
      assert {:ok, nil} = Loader.map_lookup(loader, handle, "counters", key)
    end

    test "delete existing key then lookup returns nil", %{loader: loader, handle: handle} do
      key = <<2, 0, 0, 0>>
      value = <<100, 0, 0, 0>>
      assert :ok = Loader.map_update(loader, handle, "counters", key, value)
      assert :ok = Loader.map_delete(loader, handle, "counters", key)
      assert {:ok, nil} = Loader.map_lookup(loader, handle, "counters", key)
    end

    test "delete non-existent key is idempotent", %{loader: loader, handle: handle} do
      key = <<200, 0, 0, 0>>
      assert :ok = Loader.map_delete(loader, handle, "counters", key)
    end

    test "invalid handle returns error", %{loader: loader} do
      key = <<1, 0, 0, 0>>
      assert {:error, _} = Loader.map_lookup(loader, 999, "counters", key)
    end

    test "invalid map name returns error", %{loader: loader, handle: handle} do
      key = <<1, 0, 0, 0>>
      assert {:error, _} = Loader.map_lookup(loader, handle, "no_such_map", key)
    end
  end

  describe "cleanup" do
    test "GenServer stop auto-detaches", %{loader: loader} do
      {:ok, _handle, _maps} = Loader.load_xdp_source(loader, @xdp_pass_source, "lo")
      # Stopping the GenServer closes the port, which triggers C-side cleanup
      GenServer.stop(loader)
      # If we get here without hanging, cleanup worked.
      # Re-load on the same interface should succeed
      {:ok, loader2} = Loader.start_link()
      assert {:ok, handle, _} = Loader.load_xdp_source(loader2, @xdp_pass_source, "lo")
      assert :ok = Loader.detach(loader2, handle)
      GenServer.stop(loader2)
    end
  end

  # --- Ring buffer event streaming ---

  @xdp_ringbuf_source """
  (program :xdp)
  (defmap events :ringbuf 0 0 262144)
  (extern bpf:ringbuf_output [:u64 :u64 :u64 :u64] :u64)

  (defn xdp_ringbuf [ctx :XdpMd] :u32
    (do (bpf/ringbuf_output events (u64 (. ctx :ingress_ifindex)) 4 0)
        2))
  """

  describe "ring buffer subscribe and receive events" do
    setup %{loader: loader} do
      {:ok, elf} = VaistoBpf.compile_source_to_elf(@xdp_ringbuf_source)
      {:ok, handle, map_names} = Loader.load_xdp(loader, elf, "lo")
      assert "events" in map_names

      on_exit(fn ->
        if Process.alive?(loader), do: catch_exit(Loader.detach(loader, handle))
      end)

      %{handle: handle}
    end

    test "subscribe, trigger event via ping, receive event", %{loader: loader, handle: handle} do
      assert :ok = Loader.subscribe_ringbuf(loader, handle, "events")

      # Send a packet on loopback to trigger the XDP program
      System.cmd("ping", ["-c", "1", "-W", "1", "127.0.0.1"])

      assert_receive {:ringbuf_event, ^handle, "events", data}, 2000
      assert is_binary(data)
      assert byte_size(data) == 4
    end

    test "multiple subscribers both receive events", %{loader: loader, handle: handle} do
      # Subscribe from this process
      assert :ok = Loader.subscribe_ringbuf(loader, handle, "events")

      # Subscribe from a helper process that forwards events to us
      test_pid = self()

      sub2 =
        spawn_link(fn ->
          :ok = Loader.subscribe_ringbuf(loader, handle, "events")
          send(test_pid, :sub2_ready)

          receive do
            {:ringbuf_event, _, _, _} = evt ->
              send(test_pid, {:sub2_event, evt})
          end
        end)

      assert_receive :sub2_ready, 2000

      # Trigger a packet
      System.cmd("ping", ["-c", "1", "-W", "1", "127.0.0.1"])

      # Both should receive
      assert_receive {:ringbuf_event, ^handle, "events", _data}, 2000
      assert_receive {:sub2_event, {:ringbuf_event, ^handle, "events", _}}, 2000

      Process.exit(sub2, :normal)
    end

    test "unsubscribe stops event delivery", %{loader: loader, handle: handle} do
      assert :ok = Loader.subscribe_ringbuf(loader, handle, "events")

      # Trigger and confirm we receive
      System.cmd("ping", ["-c", "1", "-W", "1", "127.0.0.1"])
      assert_receive {:ringbuf_event, ^handle, "events", _}, 2000

      # Flush any remaining events
      flush_ringbuf_events()

      # Unsubscribe
      assert :ok = Loader.unsubscribe_ringbuf(loader, handle, "events")

      # Trigger another packet — should NOT receive
      System.cmd("ping", ["-c", "1", "-W", "1", "127.0.0.1"])
      refute_receive {:ringbuf_event, _, _, _}, 500
    end

    test "subscriber process death triggers auto-cleanup", %{loader: loader, handle: handle} do
      test_pid = self()

      sub =
        spawn(fn ->
          :ok = Loader.subscribe_ringbuf(loader, handle, "events")
          send(test_pid, :sub_ready)

          receive do
            :exit -> :ok
          end
        end)

      assert_receive :sub_ready, 2000

      # Kill the subscriber
      Process.exit(sub, :kill)

      # Give the GenServer time to process the :DOWN
      Process.sleep(100)

      # The loader should still be alive and functional
      assert Process.alive?(loader)

      # Should be able to do other operations
      key = <<1, 0, 0, 0>>
      # map_lookup on a nonexistent map name for sanity
      assert {:error, _} = Loader.map_lookup(loader, handle, "nonexistent", key)
    end

    test "invalid handle returns error", %{loader: loader} do
      assert {:error, _} = Loader.subscribe_ringbuf(loader, 999, "events")
    end

    test "invalid map name returns error", %{loader: loader, handle: handle} do
      assert {:error, _} = Loader.subscribe_ringbuf(loader, handle, "no_such_map")
    end
  end

  defp flush_ringbuf_events do
    receive do
      {:ringbuf_event, _, _, _} -> flush_ringbuf_events()
    after
      0 -> :ok
    end
  end
end
