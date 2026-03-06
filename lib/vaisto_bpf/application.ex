defmodule VaistoBpf.Application do
  @moduledoc """
  OTP Application for vaisto_bpf.

  On Linux, starts the Loader and ProgramSupervisor.
  On other platforms, only schema/codec features are available.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children =
      if runtime_available?() do
        [
          {VaistoBpf.Loader, [name: VaistoBpf.Loader]},
          {DynamicSupervisor, name: VaistoBpf.ProgramSupervisor, strategy: :one_for_one}
        ]
      else
        []
      end

    Supervisor.start_link(children, strategy: :one_for_one, name: VaistoBpf.Supervisor)
  end

  @doc "Returns true if the BPF runtime (Loader) is available on this platform."
  def runtime_available? do
    case :os.type() do
      {:unix, :linux} -> true
      _ -> false
    end
  end
end
