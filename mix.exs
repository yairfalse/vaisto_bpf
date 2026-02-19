defmodule VaistoBpf.MixProject do
  use Mix.Project

  def project do
    [
      app: :vaisto_bpf,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_cwd: "c_src",
      make_error_message: "Could not compile bpf_loader. Ensure libbpf-dev is installed.",
      deps: deps(),
      description: "eBPF backend for the Vaisto programming language",
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:vaisto, path: "../vaisto"},
      {:elixir_make, "~> 0.8", runtime: false}
    ]
  end
end
