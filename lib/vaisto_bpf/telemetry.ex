defmodule VaistoBpf.Telemetry do
  @moduledoc """
  Telemetry events emitted by vaisto_bpf.

  ## Span Events (emitted as `:start` / `:stop` pairs)

      [:vaisto_bpf, :compile, :start]
        measurements: %{system_time: integer}

      [:vaisto_bpf, :compile, :stop]
        measurements: %{duration: native_time}

  ## Discrete Events

      [:vaisto_bpf, :program, :start]
        metadata: %{prog_type: atom, attach_target: String.t()}

      [:vaisto_bpf, :program, :stop]
        metadata: %{handle: integer, reason: term}

      [:vaisto_bpf, :map, :lookup]
        measurements: %{duration: native_time}
        metadata: %{map_name: atom}

      [:vaisto_bpf, :map, :update]
        measurements: %{duration: native_time}
        metadata: %{map_name: atom}

      [:vaisto_bpf, :map, :delete]
        measurements: %{duration: native_time}
        metadata: %{map_name: atom}

      [:vaisto_bpf, :ringbuf, :event]
        measurements: %{byte_size: integer}
        metadata: %{map_name: atom}

      [:vaisto_bpf, :verifier, :reject]
        metadata: %{message: String.t()}
  """

  @doc "Execute a function within a telemetry span."
  def span(event_prefix, metadata, fun) do
    :telemetry.span(event_prefix, metadata, fun)
  end

  @doc "Emit a telemetry event."
  def event(event_name, measurements \\ %{}, metadata \\ %{}) do
    :telemetry.execute(event_name, measurements, metadata)
  end
end
