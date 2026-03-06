defmodule VaistoBpf.Program do
  @moduledoc """
  GenServer wrapping a loaded BPF program with typed map access and auto-decoded events.

  Uses a `%Schema{}` to translate between Elixir terms and raw kernel binaries.

  ## Usage

      {:ok, schema} = VaistoBpf.compile_source_to_schema(source)
      {:ok, prog} = Program.start_link(schema, loader, attach_target: "eth0")

      Program.map_update(prog, :counters, 5, 100)
      {:ok, 100} = Program.map_lookup(prog, :counters, 5)

      Program.subscribe(prog, :events)
      # Receives: {:bpf_event, ref, :events, decoded_map}
  """

  use GenServer

  alias VaistoBpf.Schema
  alias VaistoBpf.Schema.{MapSchema, GlobalSchema}
  alias VaistoBpf.Loader

  defstruct [:schema, :loader, :handle, :map_names, :ref, :subscribers, monitors: %{}]

  def child_spec({schema, loader, opts}) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [schema, loader, opts]},
      restart: :temporary
    }
  end

  # -- Public API --

  @doc """
  Start a Program GenServer.

  Loads the schema's ELF binary via the loader and attaches it.

  Options:
    - `:attach_target` — required for most program types (interface name, function name, etc.)
    - `:name` — GenServer name registration
  """
  def start_link(%Schema{} = schema, loader, opts \\ []) do
    GenServer.start_link(__MODULE__, {schema, loader, opts}, Keyword.take(opts, [:name]))
  end

  @doc "Detach the program from its hook but keep the GenServer alive."
  def detach(server) do
    GenServer.call(server, :detach, :infinity)
  end

  @doc "Detach, unload, and stop the GenServer."
  def stop(server) do
    GenServer.stop(server)
  end

  @doc """
  Look up a key in a typed BPF map.

  Returns `{:ok, decoded_value}` or `{:ok, nil}` if key not found.
  """
  def map_lookup(server, map_name, key) do
    GenServer.call(server, {:map_lookup, map_name, key}, :infinity)
  end

  @doc "Update a key-value pair in a typed BPF map."
  def map_update(server, map_name, key, value) do
    GenServer.call(server, {:map_update, map_name, key, value}, :infinity)
  end

  @doc "Delete a key from a typed BPF map."
  def map_delete(server, map_name, key) do
    GenServer.call(server, {:map_delete, map_name, key}, :infinity)
  end

  @doc "Return all keys in a BPF map, decoded."
  def map_keys(server, map_name) do
    GenServer.call(server, {:map_keys, map_name}, :infinity)
  end

  @doc "Read a global variable by name."
  def get_global(server, name) do
    GenServer.call(server, {:get_global, name}, :infinity)
  end

  @doc "Write a global variable by name (only for non-const globals)."
  def set_global(server, name, value) do
    GenServer.call(server, {:set_global, name, value}, :infinity)
  end

  @doc """
  Subscribe the calling process to ring buffer events from `map_name`.

  Events arrive as `{:bpf_event, ref, map_name, decoded_term}`.
  """
  def subscribe(server, map_name) do
    GenServer.call(server, {:subscribe, map_name, self()}, :infinity)
  end

  @doc "Unsubscribe from ring buffer events."
  def unsubscribe(server, map_name) do
    GenServer.call(server, {:unsubscribe, map_name, self()}, :infinity)
  end

  # -- GenServer callbacks --

  @impl true
  def init({schema, loader, opts}) do
    prog_type = schema.prog_type || :auto
    attach_target = schema.attach_target || Keyword.get(opts, :attach_target, "")

    case Loader.load(loader, schema.elf_binary, prog_type, attach_target) do
      {:ok, handle, map_names} ->
        ref = make_ref()
        VaistoBpf.Telemetry.event(
          [:vaisto_bpf, :program, :start],
          %{},
          %{prog_type: prog_type, attach_target: attach_target}
        )

        {:ok,
         %__MODULE__{
           schema: schema,
           loader: loader,
           handle: handle,
           map_names: map_names,
           ref: ref,
           subscribers: %{}
         }}

      {:error, reason} ->
        VaistoBpf.Telemetry.event(
          [:vaisto_bpf, :verifier, :reject],
          %{},
          %{message: to_string(reason)}
        )
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:detach, _from, %{handle: nil} = state) do
    {:reply, :ok, state}
  end

  def handle_call(:detach, _from, state) do
    case Loader.detach(state.loader, state.handle) do
      :ok -> {:reply, :ok, %{state | handle: nil}}
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:map_lookup, map_name, key}, _from, state) do
    with {:ok, %MapSchema{} = ms} <- fetch_map_schema(state, map_name),
         {:ok, {enc, _}, {_, dec}} <- require_codecs(ms) do
      encoded_key = enc.(key)
      start_time = System.monotonic_time()

      result =
        case Loader.map_lookup(state.loader, state.handle, Atom.to_string(map_name), encoded_key) do
          {:ok, nil} -> {:ok, nil}
          {:ok, raw} -> {:ok, dec.(raw)}
          {:error, _} = err -> err
        end

      duration = System.monotonic_time() - start_time
      VaistoBpf.Telemetry.event([:vaisto_bpf, :map, :lookup], %{duration: duration}, %{map_name: map_name})
      {:reply, result, state}
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:map_update, map_name, key, value}, _from, state) do
    with {:ok, %MapSchema{} = ms} <- fetch_map_schema(state, map_name),
         {:ok, {enc_k, _}, {enc_v, _}} <- require_codecs(ms) do
      encoded_key = enc_k.(key)
      encoded_val = enc_v.(value)
      start_time = System.monotonic_time()

      result =
        Loader.map_update(
          state.loader,
          state.handle,
          Atom.to_string(map_name),
          encoded_key,
          encoded_val
        )

      duration = System.monotonic_time() - start_time
      VaistoBpf.Telemetry.event([:vaisto_bpf, :map, :update], %{duration: duration}, %{map_name: map_name})
      {:reply, result, state}
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:map_delete, map_name, key}, _from, state) do
    with {:ok, %MapSchema{} = ms} <- fetch_map_schema(state, map_name),
         {:ok, {enc, _}, _} <- require_key_codec(ms) do
      encoded_key = enc.(key)
      start_time = System.monotonic_time()
      result = Loader.map_delete(state.loader, state.handle, Atom.to_string(map_name), encoded_key)
      duration = System.monotonic_time() - start_time
      VaistoBpf.Telemetry.event([:vaisto_bpf, :map, :delete], %{duration: duration}, %{map_name: map_name})
      {:reply, result, state}
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:map_keys, map_name}, _from, state) do
    with {:ok, %MapSchema{} = ms} <- fetch_map_schema(state, map_name),
         {:ok, {_, dec}, _} <- require_key_codec(ms) do
      case Loader.map_keys(state.loader, state.handle, Atom.to_string(map_name)) do
        {:ok, raw_keys} -> {:reply, {:ok, Enum.map(raw_keys, dec)}, state}
        {:error, _} = err -> {:reply, err, state}
      end
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:get_global, name}, _from, state) do
    with {:ok, %GlobalSchema{} = gs} <- fetch_global_schema(state, name) do
      section_map = section_map_name(gs.section)

      case Loader.map_lookup(state.loader, state.handle, section_map, <<0::little-32>>) do
        {:ok, nil} ->
          {:reply, {:ok, nil}, state}

        {:ok, section_data} ->
          {_, dec} = gs.codec
          field_bytes = binary_part(section_data, gs.offset, gs.size)
          {:reply, {:ok, dec.(field_bytes)}, state}

        {:error, _} = err ->
          {:reply, err, state}
      end
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:set_global, name, value}, _from, state) do
    with {:ok, %GlobalSchema{} = gs} <- fetch_global_schema(state, name) do
      if gs.const? do
        {:reply, {:error, {:const_global, name}}, state}
      else
        section_map = section_map_name(gs.section)

        case Loader.map_lookup(state.loader, state.handle, section_map, <<0::little-32>>) do
          {:ok, section_data} when is_binary(section_data) ->
            {enc, _} = gs.codec
            encoded = enc.(value)

            new_data =
              <<binary_part(section_data, 0, gs.offset)::binary,
                encoded::binary,
                binary_part(section_data, gs.offset + gs.size, byte_size(section_data) - gs.offset - gs.size)::binary>>

            result =
              Loader.map_update(state.loader, state.handle, section_map, <<0::little-32>>, new_data)

            {:reply, result, state}

          {:ok, nil} ->
            {:reply, {:error, :section_not_found}, state}

          {:error, _} = err ->
            {:reply, err, state}
        end
      end
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:subscribe, map_name, pid}, _from, state) do
    with {:ok, %MapSchema{map_type: :ringbuf}} <- fetch_map_schema(state, map_name) do
      current = Map.get(state.subscribers, map_name, MapSet.new())

      if MapSet.size(current) == 0 do
        case Loader.subscribe_ringbuf(state.loader, state.handle, Atom.to_string(map_name), self()) do
          :ok ->
            state = add_subscriber(state, map_name, pid)
            {:reply, :ok, state}

          {:error, _} = err ->
            {:reply, err, state}
        end
      else
        state = add_subscriber(state, map_name, pid)
        {:reply, :ok, state}
      end
    else
      {:ok, %MapSchema{}} -> {:reply, {:error, {:not_ringbuf, map_name}}, state}
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:unsubscribe, map_name, pid}, _from, state) do
    current = Map.get(state.subscribers, map_name, MapSet.new())

    if not MapSet.member?(current, pid) do
      {:reply, :ok, state}
    else
      state = remove_subscriber(state, map_name, pid)
      remaining = Map.get(state.subscribers, map_name, MapSet.new())

      if MapSet.size(remaining) == 0 do
        case Loader.unsubscribe_ringbuf(state.loader, state.handle, Atom.to_string(map_name), self()) do
          :ok ->
            {:reply, :ok, state}

          {:error, _} = err ->
            # Revert: re-add subscriber since unsubscribe failed
            state = add_subscriber(state, map_name, pid)
            {:reply, err, state}
        end
      else
        {:reply, :ok, state}
      end
    end
  end

  @impl true
  def handle_info({:ringbuf_event, _handle, map_name, raw_data}, state) do
    case find_map_by_string_name(state.schema.maps, map_name) do
      {map_atom, %MapSchema{value_codec: {_, dec}}} when dec != nil ->
        VaistoBpf.Telemetry.event(
          [:vaisto_bpf, :ringbuf, :event],
          %{byte_size: byte_size(raw_data)},
          %{map_name: map_atom}
        )

        decoded = dec.(raw_data)

        for pid <- Map.get(state.subscribers, map_atom, MapSet.new()) do
          send(pid, {:bpf_event, state.ref, map_atom, decoded})
        end

      {map_atom, _} ->
        VaistoBpf.Telemetry.event(
          [:vaisto_bpf, :ringbuf, :event],
          %{byte_size: byte_size(raw_data)},
          %{map_name: map_atom}
        )

        for pid <- Map.get(state.subscribers, map_atom, MapSet.new()) do
          send(pid, {:bpf_event, state.ref, map_atom, raw_data})
        end

      nil ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {{map_name, ^pid}, monitors} ->
        state = %{state | monitors: monitors}
        current = Map.get(state.subscribers, map_name, MapSet.new())
        new_set = MapSet.delete(current, pid)
        state = put_in_subscribers(state, map_name, new_set)

        if MapSet.size(new_set) == 0 and MapSet.size(current) > 0 do
          Loader.unsubscribe_ringbuf(state.loader, state.handle, Atom.to_string(map_name), self())
        end

        {:noreply, state}

      {nil, _} ->
        {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(reason, %{handle: handle, loader: loader}) when handle != nil do
    VaistoBpf.Telemetry.event(
      [:vaisto_bpf, :program, :stop],
      %{},
      %{handle: handle, reason: reason}
    )
    Loader.detach(loader, handle)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # -- Private --

  defp fetch_map_schema(state, map_name) do
    case Map.fetch(state.schema.maps, map_name) do
      {:ok, ms} -> {:ok, ms}
      :error -> {:error, {:unknown_map, map_name}}
    end
  end

  defp fetch_global_schema(state, name) do
    case Map.fetch(state.schema.globals, name) do
      {:ok, gs} -> {:ok, gs}
      :error -> {:error, {:unknown_global, name}}
    end
  end

  defp require_codecs(%MapSchema{key_codec: nil, name: name}),
    do: {:error, {:missing_codec, name}}
  defp require_codecs(%MapSchema{value_codec: nil, name: name}),
    do: {:error, {:missing_codec, name}}
  defp require_codecs(%MapSchema{key_codec: kc, value_codec: vc}),
    do: {:ok, kc, vc}

  defp require_key_codec(%MapSchema{key_codec: nil, name: name}),
    do: {:error, {:missing_codec, name}}
  defp require_key_codec(%MapSchema{key_codec: kc, value_codec: vc}),
    do: {:ok, kc, vc}

  defp section_map_name(:bss), do: ".bss"
  defp section_map_name(:data), do: ".data"
  defp section_map_name(:rodata), do: ".rodata"

  defp add_subscriber(state, map_name, pid) do
    ref = Process.monitor(pid)
    current = Map.get(state.subscribers, map_name, MapSet.new())
    state = put_in_subscribers(state, map_name, MapSet.put(current, pid))
    %{state | monitors: Map.put(state.monitors, ref, {map_name, pid})}
  end

  defp remove_subscriber(state, map_name, pid) do
    {ref, monitors} =
      Enum.reduce(state.monitors, {nil, state.monitors}, fn {r, {mn, p}}, {found, acc} ->
        if mn == map_name and p == pid do
          {r, Map.delete(acc, r)}
        else
          {found, acc}
        end
      end)

    if ref, do: Process.demonitor(ref, [:flush])

    current = Map.get(state.subscribers, map_name, MapSet.new())
    new_set = MapSet.delete(current, pid)
    state = put_in_subscribers(%{state | monitors: monitors}, map_name, new_set)
    state
  end

  defp put_in_subscribers(state, map_name, set) do
    %{state | subscribers: Map.put(state.subscribers, map_name, set)}
  end

  defp find_map_by_string_name(schema_maps, name_str) do
    Enum.find_value(schema_maps, fn {k, v} ->
      if Atom.to_string(k) == name_str, do: {k, v}
    end)
  end
end
