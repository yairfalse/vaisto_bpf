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

  @doc "Look up a key in a BPF map. Returns `{:ok, binary}` if found, `{:ok, nil}` if not."
  @spec map_lookup(GenServer.server(), non_neg_integer(), String.t(), binary()) ::
          {:ok, binary() | nil} | {:error, String.t()}
  def map_lookup(server, handle, map_name, key) do
    GenServer.call(server, {:map_lookup, handle, map_name, key}, :infinity)
  end

  @doc "Update (insert/overwrite) a key-value pair in a BPF map."
  @spec map_update(GenServer.server(), non_neg_integer(), String.t(), binary(), binary(), non_neg_integer()) ::
          :ok | {:error, String.t()}
  def map_update(server, handle, map_name, key, value, flags \\ 0) do
    GenServer.call(server, {:map_update, handle, map_name, key, value, flags}, :infinity)
  end

  @doc "Delete a key from a BPF map. Returns `:ok` even if key didn't exist."
  @spec map_delete(GenServer.server(), non_neg_integer(), String.t(), binary()) ::
          :ok | {:error, String.t()}
  def map_delete(server, handle, map_name, key) do
    GenServer.call(server, {:map_delete, handle, map_name, key}, :infinity)
  end

  @doc """
  Get the next key in a BPF map after `key`.
  Pass `nil` as key to get the first key.
  Returns `{:ok, next_key}` or `{:ok, nil}` when iteration is complete.
  """
  @spec map_get_next_key(GenServer.server(), non_neg_integer(), String.t(), binary() | nil) ::
          {:ok, binary() | nil} | {:error, String.t()}
  def map_get_next_key(server, handle, map_name, key \\ nil) do
    GenServer.call(server, {:map_get_next_key, handle, map_name, key}, :infinity)
  end

  @doc """
  Return all keys in a BPF map as a list of binaries.
  Iterates using `map_get_next_key` until exhausted.
  """
  @spec map_keys(GenServer.server(), non_neg_integer(), String.t()) ::
          {:ok, [binary()]} | {:error, String.t()}
  def map_keys(server, handle, map_name) do
    collect_keys(server, handle, map_name, nil, [])
  end

  defp collect_keys(server, handle, map_name, current_key, acc) do
    case map_get_next_key(server, handle, map_name, current_key) do
      {:ok, nil} -> {:ok, Enum.reverse(acc)}
      {:ok, next_key} -> collect_keys(server, handle, map_name, next_key, [next_key | acc])
      {:error, _} = err -> err
    end
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

  @doc """
  Subscribe a process to ring buffer events from a BPF map.

  Events arrive as `{:ringbuf_event, handle, map_name, data}` messages.
  The first subscriber for a given `{handle, map_name}` triggers a C-level
  subscription. Subsequent subscribers are tracked locally.
  """
  @spec subscribe_ringbuf(GenServer.server(), non_neg_integer(), String.t(), pid()) ::
          :ok | {:error, String.t()}
  def subscribe_ringbuf(server, handle, map_name, subscriber \\ self()) do
    GenServer.call(server, {:subscribe_ringbuf, handle, map_name, subscriber}, :infinity)
  end

  @doc """
  Unsubscribe a process from ring buffer events.

  When the last subscriber is removed, the C-level subscription is torn down.
  """
  @spec unsubscribe_ringbuf(GenServer.server(), non_neg_integer(), String.t(), pid()) ::
          :ok | {:error, String.t()}
  def unsubscribe_ringbuf(server, handle, map_name, subscriber \\ self()) do
    GenServer.call(server, {:unsubscribe_ringbuf, handle, map_name, subscriber}, :infinity)
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

        {:ok,
         %{
           port: port,
           handles: %{},
           pending: nil,
           subscribers: %{},
           monitors: %{}
         }}
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

  def handle_call({:map_lookup, handle, map_name, key}, from, %{pending: nil} = state) do
    data = Protocol.encode_map_lookup(handle, map_name, key)
    Port.command(state.port, data)
    {:noreply, %{state | pending: {from, :map_lookup, nil}}}
  end

  def handle_call({:map_update, handle, map_name, key, value, flags}, from, %{pending: nil} = state) do
    data = Protocol.encode_map_update(handle, map_name, key, value, flags)
    Port.command(state.port, data)
    {:noreply, %{state | pending: {from, :map_update, nil}}}
  end

  def handle_call({:map_delete, handle, map_name, key}, from, %{pending: nil} = state) do
    data = Protocol.encode_map_delete(handle, map_name, key)
    Port.command(state.port, data)
    {:noreply, %{state | pending: {from, :map_delete, nil}}}
  end

  def handle_call({:map_get_next_key, handle, map_name, key}, from, %{pending: nil} = state) do
    data = Protocol.encode_map_get_next_key(handle, map_name, key)
    Port.command(state.port, data)
    {:noreply, %{state | pending: {from, :map_get_next_key, nil}}}
  end

  def handle_call({:subscribe_ringbuf, handle, map_name, pid}, from, %{pending: nil} = state) do
    key = {handle, map_name}
    current = Map.get(state.subscribers, key, MapSet.new())

    if MapSet.size(current) == 0 do
      # First subscriber — send subscribe command to C port
      data = Protocol.encode_subscribe_ringbuf(handle, map_name)
      Port.command(state.port, data)
      {:noreply, %{state | pending: {from, :subscribe_ringbuf, {key, pid}}}}
    else
      # Already subscribed at C level — just add locally
      state = add_subscriber(state, key, pid)
      {:reply, :ok, state}
    end
  end

  def handle_call({:unsubscribe_ringbuf, handle, map_name, pid}, from, %{pending: nil} = state) do
    key = {handle, map_name}
    current = Map.get(state.subscribers, key, MapSet.new())

    if not MapSet.member?(current, pid) do
      {:reply, :ok, state}
    else
      state = remove_subscriber(state, key, pid)
      new_current = Map.get(state.subscribers, key, MapSet.new())

      if MapSet.size(new_current) == 0 do
        # Last subscriber — unsubscribe at C level
        data = Protocol.encode_unsubscribe_ringbuf(handle, map_name)
        Port.command(state.port, data)
        {:noreply, %{state | pending: {from, :unsubscribe_ringbuf, nil}}}
      else
        {:reply, :ok, state}
      end
    end
  end

  def handle_call(_msg, _from, %{pending: pending} = state) when pending != nil do
    {:reply, {:error, "loader busy"}, state}
  end

  @impl true
  # Ring buffer events (0x10) — can arrive ANY time, even with pending != nil
  def handle_info({port, {:data, <<0x10, _::binary>> = data}}, %{port: port} = state) do
    case Protocol.decode_event(data) do
      {:ringbuf_event, handle, map_name, event_data} ->
        notify_subscribers(state, handle, map_name, event_data)

      _ ->
        :ok
    end

    {:noreply, state}
  end

  # Drain response — fire-and-forget unsubscribe from :DOWN handler.
  # Events (0x10) are already matched above, so this only catches command responses.
  def handle_info({port, {:data, _data}}, %{port: port, pending: {:drain, _cmd, _extra}} = state) do
    {:noreply, %{state | pending: nil}}
  end

  # Command responses — existing logic (pending must be set)
  def handle_info({port, {:data, data}}, %{port: port, pending: {from, cmd, extra}} = state) do
    result =
      case Protocol.decode_response(cmd, data) do
        {:ok, %{handle: handle, map_names: map_names}} ->
          new_handles =
            Map.put(state.handles, handle, %{interface: extra, map_names: map_names})

          {:reply_state, {:ok, handle, map_names}, %{state | handles: new_handles}}

        {:ok, value} when cmd in [:map_lookup, :map_get_next_key] ->
          {:reply_state, {:ok, value}, state}

        :ok when cmd == :detach ->
          new_handles = Map.delete(state.handles, extra)
          {:reply_state, :ok, %{state | handles: new_handles}}

        :ok when cmd in [:map_update, :map_delete] ->
          {:reply_state, :ok, state}

        :ok when cmd == :subscribe_ringbuf ->
          {key, pid} = extra
          state = add_subscriber(state, key, pid)
          {:reply_state, :ok, state}

        :ok when cmd == :unsubscribe_ringbuf ->
          {:reply_state, :ok, state}

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
      {:drain, _cmd, _extra} ->
        :ok

      {from, _cmd, _extra} ->
        GenServer.reply(from, {:error, "port exited with status #{status}"})

      nil ->
        :ok
    end

    {:stop, reason, %{state | pending: nil}}
  end

  # Subscriber process died — clean up
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {{pid, handle, map_name}, monitors} ->
        key = {handle, map_name}
        current = Map.get(state.subscribers, key, MapSet.new())
        subs = MapSet.delete(current, pid)

        if MapSet.size(subs) == 0 do
          subscribers = Map.delete(state.subscribers, key)
          state = %{state | subscribers: subscribers, monitors: monitors}

          if state.pending == nil do
            # Can send unsubscribe now
            data = Protocol.encode_unsubscribe_ringbuf(handle, map_name)
            Port.command(state.port, data)
            {:noreply, %{state | pending: {:drain, :unsubscribe_ringbuf, nil}}}
          else
            # Busy — queue for later. The C subscription stays alive but
            # events won't be forwarded (no subscribers). It gets cleaned
            # up when the program is detached or port closes.
            {:noreply, state}
          end
        else
          subscribers = Map.put(state.subscribers, key, subs)
          {:noreply, %{state | subscribers: subscribers, monitors: monitors}}
        end

      {nil, _} ->
        {:noreply, state}
    end
  end

  @impl true
  def terminate(_reason, %{port: port}) do
    if Port.info(port) != nil do
      Port.close(port)
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok

  # -- Private: subscriber management --

  defp add_subscriber(state, key, pid) do
    ref = Process.monitor(pid)
    {handle, map_name} = key
    subs = Map.update(state.subscribers, key, MapSet.new([pid]), &MapSet.put(&1, pid))
    mons = Map.put(state.monitors, ref, {pid, handle, map_name})
    %{state | subscribers: subs, monitors: mons}
  end

  defp remove_subscriber(state, key, pid) do
    {handle, map_name} = key

    # Find and remove the monitor for this pid + key
    {ref, monitors} =
      Enum.reduce(state.monitors, {nil, state.monitors}, fn {r, {p, h, m}}, {found, acc} ->
        if p == pid and h == handle and m == map_name do
          {r, Map.delete(acc, r)}
        else
          {found, acc}
        end
      end)

    if ref, do: Process.demonitor(ref, [:flush])

    subs = MapSet.delete(Map.get(state.subscribers, key, MapSet.new()), pid)

    subscribers =
      if MapSet.size(subs) == 0,
        do: Map.delete(state.subscribers, key),
        else: Map.put(state.subscribers, key, subs)

    %{state | subscribers: subscribers, monitors: monitors}
  end

  defp notify_subscribers(state, handle, map_name, data) do
    key = {handle, map_name}

    for pid <- Map.get(state.subscribers, key, MapSet.new()) do
      send(pid, {:ringbuf_event, handle, map_name, data})
    end
  end

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
