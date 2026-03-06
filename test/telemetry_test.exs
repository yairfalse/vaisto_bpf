defmodule VaistoBpf.TelemetryTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Telemetry

  describe "event/3" do
    test "emits telemetry event" do
      ref = make_ref()
      test_pid = self()

      handler_id = "test-#{inspect(ref)}"

      :telemetry.attach(
        handler_id,
        [:vaisto_bpf, :test, :event],
        fn event, measurements, metadata, _config ->
          send(test_pid, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      Telemetry.event([:vaisto_bpf, :test, :event], %{duration: 42}, %{map_name: :counters})

      assert_receive {:telemetry, [:vaisto_bpf, :test, :event], %{duration: 42}, %{map_name: :counters}}
    end
  end

  describe "span/3" do
    test "emits start and stop events" do
      ref = make_ref()
      test_pid = self()

      handler_id = "test-span-#{inspect(ref)}"

      :telemetry.attach_many(
        handler_id,
        [
          [:vaisto_bpf, :test, :span, :start],
          [:vaisto_bpf, :test, :span, :stop]
        ],
        fn event, measurements, metadata, _config ->
          send(test_pid, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      result = Telemetry.span([:vaisto_bpf, :test, :span], %{key: :val}, fn ->
        {42, %{key: :val}}
      end)

      assert result == 42

      assert_receive {:telemetry, [:vaisto_bpf, :test, :span, :start], _, %{key: :val}}
      assert_receive {:telemetry, [:vaisto_bpf, :test, :span, :stop], %{duration: _}, %{key: :val}}
    end
  end
end
