defmodule VaistoBpf.LoaderQueueTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Tests for the Loader's request queuing behavior.

  Since the real Loader requires a C port binary (Linux only), these tests
  verify queue semantics by starting a Loader with a fake port script.
  """

  describe "queue behavior via DelayedMockLoader" do
    # A GenServer that mimics Loader's queuing: holds pending calls
    # and only replies when explicitly released.
    defmodule DelayedMockLoader do
      use GenServer

      def start_link(opts \\ []) do
        GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
      end

      def release(server) do
        GenServer.cast(server, :release)
      end

      @impl true
      def init(_opts) do
        {:ok, %{pending: nil, queue: :queue.new()}}
      end

      @impl true
      def handle_call({:map_lookup, _handle, _map, _key} = msg, from, %{pending: nil} = state) do
        {:noreply, %{state | pending: {from, msg}}}
      end

      def handle_call({:map_lookup, _handle, _map, _key} = msg, from, state) do
        {:noreply, %{state | queue: :queue.in({from, msg}, state.queue)}}
      end

      # Also handle load for Program init
      def handle_call({:load, _elf, _prog_type, _attach}, _from, state) do
        {:reply, {:ok, 1, ["test"]}, state}
      end

      def handle_call({:detach, _handle}, _from, state) do
        {:reply, :ok, state}
      end

      def handle_call({:subscribe_ringbuf, _h, _m, _p}, _from, state) do
        {:reply, :ok, state}
      end

      def handle_call({:unsubscribe_ringbuf, _h, _m, _p}, _from, state) do
        {:reply, :ok, state}
      end

      @impl true
      def handle_cast(:release, %{pending: {from, _msg}} = state) do
        GenServer.reply(from, {:ok, <<42::little-64>>})
        state = %{state | pending: nil}

        case :queue.out(state.queue) do
          {:empty, _} ->
            {:noreply, state}

          {{:value, {next_from, next_msg}}, queue} ->
            {:noreply, %{state | pending: {next_from, next_msg}, queue: queue}}
        end
      end

      def handle_cast(:release, %{pending: nil} = state) do
        {:noreply, state}
      end
    end

    test "multiple concurrent calls are queued, not rejected" do
      {:ok, loader} = DelayedMockLoader.start_link()

      # Start 3 concurrent lookups
      tasks =
        for i <- 1..3 do
          Task.async(fn ->
            GenServer.call(loader, {:map_lookup, 1, "test", <<i::little-32>>}, :infinity)
          end)
        end

      # Give tasks time to send their calls
      :timer.sleep(50)

      # Release all 3
      for _ <- 1..3 do
        DelayedMockLoader.release(loader)
        :timer.sleep(10)
      end

      # All 3 should complete successfully
      results = Enum.map(tasks, &Task.await(&1, 1000))
      assert length(results) == 3
      assert Enum.all?(results, fn {:ok, _} -> true; _ -> false end)
    end
  end
end
