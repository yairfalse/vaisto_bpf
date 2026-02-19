defmodule VaistoBpf.Loader do
  @moduledoc """
  GenServer that manages a C port for loading BPF programs into the kernel.

  The port binary (`priv/bpf_loader`) is only available on Linux.
  On other platforms, `start_link/1` returns `{:error, :loader_not_available}`.
  """

  use GenServer

  alias VaistoBpf.Loader.Protocol

  # -- Public API --

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
  end

  @doc "Load an XDP program from an ELF binary and attach it to `interface`."
  @spec load_xdp(GenServer.server(), binary(), String.t()) ::
          {:ok, non_neg_integer(), [String.t()]} | {:error, String.t()}
  def load_xdp(server, elf_binary, interface) do
    GenServer.call(server, {:load_xdp, elf_binary, interface}, :infinity)
  end

  @doc "Detach and unload a previously loaded program by handle."
  @spec detach(GenServer.server(), non_neg_integer()) :: :ok | {:error, String.t()}
  def detach(server, handle) do
    GenServer.call(server, {:detach, handle}, :infinity)
  end

  @doc "Compile Vaisto source to ELF, then load and attach as XDP on `interface`."
  @spec load_xdp_source(GenServer.server(), String.t(), String.t()) ::
          {:ok, non_neg_integer(), [String.t()]} | {:error, String.t()}
  def load_xdp_source(server, source, interface) do
    case VaistoBpf.compile_source_to_elf(source) do
      {:ok, elf_binary} -> load_xdp(server, elf_binary, interface)
      {:error, _} = err -> err
    end
  end

  # -- GenServer callbacks --

  @impl true
  def init(_opts) do
    port_path = port_executable()

    case port_path do
      {:error, reason} ->
        {:stop, reason}

      path ->
        port =
          Port.open({:spawn_executable, path}, [
            :binary,
            :exit_status,
            {:packet, 2}
          ])

        {:ok, %{port: port, handles: %{}, pending: nil}}
    end
  end

  @impl true
  def handle_call({:load_xdp, elf_binary, interface}, from, %{pending: nil} = state) do
    data = Protocol.encode_load_xdp(elf_binary, interface)
    Port.command(state.port, data)
    {:noreply, %{state | pending: {from, :load_xdp, interface}}}
  end

  def handle_call({:detach, handle}, from, %{pending: nil} = state) do
    data = Protocol.encode_detach(handle)
    Port.command(state.port, data)
    {:noreply, %{state | pending: {from, :detach, handle}}}
  end

  def handle_call(_msg, _from, %{pending: pending} = state) when pending != nil do
    {:reply, {:error, "loader busy"}, state}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port, pending: {from, cmd, extra}} = state) do
    result =
      case Protocol.decode_response(cmd, data) do
        {:ok, %{handle: handle, map_names: map_names}} ->
          new_handles =
            Map.put(state.handles, handle, %{interface: extra, map_names: map_names})

          {:reply_state, {:ok, handle, map_names}, %{state | handles: new_handles}}

        :ok ->
          new_handles = Map.delete(state.handles, extra)
          {:reply_state, :ok, %{state | handles: new_handles}}

        {:error, _} = err ->
          {:reply_state, err, state}
      end

    case result do
      {:reply_state, reply, new_state} ->
        GenServer.reply(from, reply)
        {:noreply, %{new_state | pending: nil}}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    reason = {:port_exit, status}

    case state.pending do
      {from, _cmd, _extra} ->
        GenServer.reply(from, {:error, "port exited with status #{status}"})

      nil ->
        :ok
    end

    {:stop, reason, %{state | pending: nil}}
  end

  @impl true
  def terminate(_reason, %{port: port}) do
    if Port.info(port) != nil do
      Port.close(port)
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok

  # -- Private --

  defp port_executable do
    case :code.priv_dir(:vaisto_bpf) do
      {:error, :bad_name} ->
        {:error, :loader_not_available}

      priv_dir ->
        path = Path.join(to_string(priv_dir), "bpf_loader")

        if File.exists?(path) do
          String.to_charlist(path)
        else
          {:error, :loader_not_available}
        end
    end
  end
end
