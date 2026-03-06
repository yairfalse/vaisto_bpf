defmodule VaistoBpf.ProgramTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Schema
  alias VaistoBpf.Schema.{MapSchema, GlobalSchema}
  alias VaistoBpf.Codec
  alias VaistoBpf.Program

  # ==========================================================================
  # Mock Loader — a GenServer that simulates the real Loader's API
  # ==========================================================================

  defmodule MockLoader do
    use GenServer

    def start_link(opts \\ []) do
      GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
    end

    @impl true
    def init(_opts) do
      {:ok, %{maps: %{}, handle_counter: 0, ringbuf_subscribers: %{},
              detach_calls: [], unsubscribe_calls: []}}
    end

    @impl true
    def handle_call(:get_detach_calls, _from, state) do
      {:reply, state.detach_calls, state}
    end

    def handle_call(:get_unsubscribe_calls, _from, state) do
      {:reply, state.unsubscribe_calls, state}
    end

    def handle_call({:load, _elf, _prog_type, _attach}, _from, state) do
      handle = state.handle_counter + 1
      state = %{state | handle_counter: handle}
      {:reply, {:ok, handle, ["counters", "events", ".bss"]}, state}
    end

    def handle_call({:detach, handle}, _from, state) do
      state = %{state | detach_calls: [handle | state.detach_calls]}
      {:reply, :ok, state}
    end

    def handle_call({:map_lookup, _handle, map_name, key}, _from, state) do
      map_key = {map_name, key}

      case Map.get(state.maps, map_key) do
        nil -> {:reply, {:ok, nil}, state}
        value -> {:reply, {:ok, value}, state}
      end
    end

    def handle_call({:map_update, _handle, map_name, key, value, _flags}, _from, state) do
      map_key = {map_name, key}
      state = %{state | maps: Map.put(state.maps, map_key, value)}
      {:reply, :ok, state}
    end

    def handle_call({:map_delete, _handle, map_name, key}, _from, state) do
      map_key = {map_name, key}
      state = %{state | maps: Map.delete(state.maps, map_key)}
      {:reply, :ok, state}
    end

    def handle_call({:map_get_next_key, _handle, map_name, nil}, _from, state) do
      keys =
        state.maps
        |> Map.keys()
        |> Enum.filter(fn {mn, _} -> mn == map_name end)
        |> Enum.map(fn {_, k} -> k end)
        |> Enum.sort()

      case keys do
        [first | _] -> {:reply, {:ok, first}, state}
        [] -> {:reply, {:ok, nil}, state}
      end
    end

    def handle_call({:map_get_next_key, _handle, map_name, current}, _from, state) do
      keys =
        state.maps
        |> Map.keys()
        |> Enum.filter(fn {mn, _} -> mn == map_name end)
        |> Enum.map(fn {_, k} -> k end)
        |> Enum.sort()

      next =
        keys
        |> Enum.drop_while(fn k -> k <= current end)
        |> List.first()

      {:reply, {:ok, next}, state}
    end

    def handle_call({:subscribe_ringbuf, _handle, _map_name, _pid}, _from, state) do
      {:reply, :ok, state}
    end

    def handle_call({:unsubscribe_ringbuf, _handle, map_name, _pid}, _from, state) do
      state = %{state | unsubscribe_calls: [map_name | state.unsubscribe_calls]}
      {:reply, :ok, state}
    end
  end

  # ==========================================================================
  # Test helpers
  # ==========================================================================

  defp build_schema(opts \\ []) do
    {key_enc, key_dec} = Codec.for_type(:u32)
    {val_enc, val_dec} = Codec.for_type(:u64)

    maps =
      Map.merge(
        %{
          counters: %MapSchema{
            name: :counters,
            map_type: :hash,
            key_type: :u32,
            value_type: :u64,
            max_entries: 1024,
            key_codec: {key_enc, key_dec},
            value_codec: {val_enc, val_dec}
          }
        },
        Keyword.get(opts, :extra_maps, %{})
      )

    globals = Keyword.get(opts, :globals, %{})

    %Schema{
      elf_binary: "fake_elf",
      prog_type: :xdp,
      section_name: "xdp",
      maps: maps,
      globals: globals,
      records: %{},
      functions: []
    }
  end

  defp start_program(schema_opts \\ []) do
    {:ok, loader} = MockLoader.start_link()
    schema = build_schema(schema_opts)
    {:ok, prog} = Program.start_link(schema, loader)
    {prog, loader}
  end

  # ==========================================================================
  # Tests
  # ==========================================================================

  describe "lifecycle" do
    test "start_link and stop" do
      {prog, _loader} = start_program()
      assert Process.alive?(prog)
      Program.stop(prog)
      refute Process.alive?(prog)
    end

    test "detach sets handle to nil" do
      {prog, _loader} = start_program()
      assert :ok = Program.detach(prog)
      # Detach again is ok
      assert :ok = Program.detach(prog)
      Program.stop(prog)
    end
  end

  describe "typed map operations" do
    test "map_update and map_lookup round-trip" do
      {prog, _loader} = start_program()

      assert :ok = Program.map_update(prog, :counters, 5, 100)
      assert {:ok, 100} = Program.map_lookup(prog, :counters, 5)

      Program.stop(prog)
    end

    test "map_lookup returns nil for missing key" do
      {prog, _loader} = start_program()

      assert {:ok, nil} = Program.map_lookup(prog, :counters, 999)

      Program.stop(prog)
    end

    test "map_delete removes key" do
      {prog, _loader} = start_program()

      Program.map_update(prog, :counters, 1, 10)
      assert {:ok, 10} = Program.map_lookup(prog, :counters, 1)

      assert :ok = Program.map_delete(prog, :counters, 1)
      assert {:ok, nil} = Program.map_lookup(prog, :counters, 1)

      Program.stop(prog)
    end

    test "map_keys returns decoded keys" do
      {prog, _loader} = start_program()

      Program.map_update(prog, :counters, 10, 100)
      Program.map_update(prog, :counters, 20, 200)

      {:ok, keys} = Program.map_keys(prog, :counters)
      assert Enum.sort(keys) == [10, 20]

      Program.stop(prog)
    end

    test "unknown map name returns error" do
      {prog, _loader} = start_program()

      assert {:error, {:unknown_map, :nonexistent}} = Program.map_lookup(prog, :nonexistent, 1)

      Program.stop(prog)
    end
  end

  describe "globals" do
    test "get_global reads from section map" do
      {global_enc, _} = Codec.for_type(:u64)
      {_, global_dec} = Codec.for_type(:u64)

      globals = %{
        counter: %GlobalSchema{
          name: :counter,
          type: :u64,
          section: :bss,
          offset: 0,
          size: 8,
          const?: false,
          codec: {global_enc, global_dec}
        }
      }

      {:ok, loader} = MockLoader.start_link()
      schema = build_schema(globals: globals)
      {:ok, prog} = Program.start_link(schema, loader)

      # Pre-populate the .bss section map in the mock
      section_data = <<42::little-64>>
      GenServer.call(loader, {:map_update, 1, ".bss", <<0::little-32>>, section_data, 0})

      assert {:ok, 42} = Program.get_global(prog, :counter)

      Program.stop(prog)
    end

    test "set_global on const returns error" do
      {enc, dec} = Codec.for_type(:u32)

      globals = %{
        max_val: %GlobalSchema{
          name: :max_val,
          type: :u32,
          section: :rodata,
          offset: 0,
          size: 4,
          const?: true,
          codec: {enc, dec}
        }
      }

      {:ok, loader} = MockLoader.start_link()
      schema = build_schema(globals: globals)
      {:ok, prog} = Program.start_link(schema, loader)

      assert {:error, {:const_global, :max_val}} = Program.set_global(prog, :max_val, 50)

      Program.stop(prog)
    end

    test "unknown global returns error" do
      {prog, _loader} = start_program()

      assert {:error, {:unknown_global, :nope}} = Program.get_global(prog, :nope)

      Program.stop(prog)
    end
  end

  describe "ring buffer subscription" do
    test "subscribe to ringbuf map" do
      ringbuf_map = %MapSchema{
        name: :events,
        map_type: :ringbuf,
        key_type: :none,
        value_type: :u64,
        max_entries: 4096,
        key_codec: nil,
        value_codec: Codec.for_type(:u64)
      }

      {:ok, loader} = MockLoader.start_link()
      schema = build_schema(extra_maps: %{events: ringbuf_map})
      {:ok, prog} = Program.start_link(schema, loader)

      assert :ok = Program.subscribe(prog, :events)

      # Simulate a ringbuf event
      send(prog, {:ringbuf_event, 1, "events", <<42::little-64>>})

      assert_receive {:bpf_event, _ref, :events, 42}, 1000

      Program.stop(prog)
    end

    test "subscribe to non-ringbuf map returns error" do
      {prog, _loader} = start_program()

      assert {:error, {:not_ringbuf, :counters}} = Program.subscribe(prog, :counters)

      Program.stop(prog)
    end

    test "unknown map name in ringbuf event is silently dropped (no crash)" do
      {prog, _loader} = start_program()

      # Send a ringbuf event for a map name that has no corresponding atom in schema
      send(prog, {:ringbuf_event, 1, "totally_unknown_map", <<1, 2, 3>>})

      # Give the GenServer time to process
      :timer.sleep(50)
      assert Process.alive?(prog)

      Program.stop(prog)
    end
  end

  describe "set_global happy path" do
    test "set_global and get_global round-trip" do
      {enc, dec} = Codec.for_type(:u64)

      globals = %{
        counter: %GlobalSchema{
          name: :counter,
          type: :u64,
          section: :bss,
          offset: 0,
          size: 8,
          const?: false,
          codec: {enc, dec}
        }
      }

      {:ok, loader} = MockLoader.start_link()
      schema = build_schema(globals: globals)
      {:ok, prog} = Program.start_link(schema, loader)

      # Pre-populate the .bss section with initial data (counter = 0)
      initial_data = <<0::little-64>>
      GenServer.call(loader, {:map_update, 1, ".bss", <<0::little-32>>, initial_data, 0})

      # Set the global
      assert :ok = Program.set_global(prog, :counter, 99)

      # Read it back
      assert {:ok, 99} = Program.get_global(prog, :counter)

      Program.stop(prog)
    end
  end

  describe "subscriber cleanup on process death" do
    test "dead subscriber is removed and unsubscribe_ringbuf is called" do
      ringbuf_map = %MapSchema{
        name: :events,
        map_type: :ringbuf,
        key_type: :none,
        value_type: :u64,
        max_entries: 4096,
        key_codec: nil,
        value_codec: Codec.for_type(:u64)
      }

      {:ok, loader} = MockLoader.start_link()
      schema = build_schema(extra_maps: %{events: ringbuf_map})
      {:ok, prog} = Program.start_link(schema, loader)

      # Spawn a process that subscribes, then dies
      test_pid = self()
      subscriber = spawn(fn ->
        send(test_pid, :ready)
        receive do :stop -> :ok end
      end)

      receive do :ready -> :ok end

      # Subscribe the spawned process (we need to call from within that process)
      # Instead, use GenServer.call directly
      :ok = GenServer.call(prog, {:subscribe, :events, subscriber})

      # Verify subscriber is in state
      state = :sys.get_state(prog)
      assert MapSet.member?(state.subscribers[:events], subscriber)
      assert map_size(state.monitors) == 1

      # Kill the subscriber
      Process.exit(subscriber, :kill)
      :timer.sleep(50)

      # Verify cleanup
      state = :sys.get_state(prog)
      remaining = Map.get(state.subscribers, :events, MapSet.new())
      assert MapSet.size(remaining) == 0
      assert map_size(state.monitors) == 0

      # Verify unsubscribe was called on the loader
      unsubscribe_calls = GenServer.call(loader, :get_unsubscribe_calls)
      assert "events" in unsubscribe_calls

      Program.stop(prog)
    end
  end

  describe "terminate calls detach" do
    test "Program.stop triggers detach on the loader" do
      {:ok, loader} = MockLoader.start_link()
      schema = build_schema()
      {:ok, prog} = Program.start_link(schema, loader)

      # Get the handle that was assigned
      state = :sys.get_state(prog)
      handle = state.handle
      assert handle != nil

      Program.stop(prog)

      # Give terminate time to execute
      :timer.sleep(50)

      detach_calls = GenServer.call(loader, :get_detach_calls)
      assert handle in detach_calls
    end
  end
end
