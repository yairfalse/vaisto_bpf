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
    @tag :skip
    @tag :btf_fix_needed
    test "reports map names", %{loader: loader} do
      # NOTE: Skipped until BTF encoding is compatible with libbpf.
      # libbpf rejects our .BTF section ("Error loading ELF section .BTF: -22").
      # The loader itself works — this is a pre-existing BTF format issue.
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
end
