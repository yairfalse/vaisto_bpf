defmodule VaistoBpf.ContextValidationTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.BpfTypeChecker

  # Helper: parse and normalize a source snippet, returning {normalized_ast, maps}
  defp prepare(source) do
    {cleaned, _section, _prog_type} = VaistoBpf.Preprocessor.extract_program(source)
    {cleaned, maps} = VaistoBpf.Preprocessor.extract_defmaps(cleaned)
    preprocessed = VaistoBpf.Preprocessor.preprocess_source(cleaned)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = VaistoBpf.Preprocessor.normalize_ast(parsed)
    {normalized, maps}
  end

  describe "correct context passes" do
    test "xdp with XdpMd parameter" do
      source = """
      (defn handler [ctx :XdpMd] :u32
        (. ctx :data))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :xdp)
    end

    test "tc with SkBuff parameter" do
      source = """
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :tc)
    end

    test "kprobe with PtRegs parameter" do
      source = """
      (defn handler [ctx :PtRegs] :u64
        (. ctx :rdi))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :kprobe)
    end

    test "sk_skb with SkBuff parameter" do
      source = """
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :sk_skb)
    end

    test "perf_event with PtRegs parameter" do
      source = """
      (defn handler [ctx :PtRegs] :u64
        (. ctx :rdi))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :perf_event)
    end
  end

  describe "wrong context fails" do
    test "xdp with SkBuff parameter" do
      source = """
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      {ast, maps} = prepare(source)
      assert {:error, err} = BpfTypeChecker.check(ast, maps, :xdp)
      assert err.message =~ "wrong context type for :xdp"
      assert err.message =~ "expected XdpMd"
      assert err.message =~ "got SkBuff"
    end

    test "tc with XdpMd parameter" do
      source = """
      (defn handler [ctx :XdpMd] :u32
        (. ctx :data))
      """
      {ast, maps} = prepare(source)
      assert {:error, err} = BpfTypeChecker.check(ast, maps, :tc)
      assert err.message =~ "wrong context type for :tc"
      assert err.message =~ "expected SkBuff"
      assert err.message =~ "got XdpMd"
    end

    test "kprobe with XdpMd parameter" do
      source = """
      (defn handler [ctx :XdpMd] :u32
        (. ctx :data))
      """
      {ast, maps} = prepare(source)
      assert {:error, err} = BpfTypeChecker.check(ast, maps, :kprobe)
      assert err.message =~ "wrong context type for :kprobe"
      assert err.message =~ "expected PtRegs"
      assert err.message =~ "got XdpMd"
    end

    test "cgroup_sock with SkBuff parameter" do
      source = """
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      {ast, maps} = prepare(source)
      assert {:error, err} = BpfTypeChecker.check(ast, maps, :cgroup_sock)
      assert err.message =~ "wrong context type for :cgroup_sock"
      assert err.message =~ "expected BpfSock"
    end
  end

  describe "nil-context types skip validation" do
    test "tracepoint allows any context (nil mapping)" do
      source = """
      (defn handler [ctx :XdpMd] :u32
        (. ctx :data))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :tracepoint)
    end

    test "lsm allows any context (nil mapping)" do
      source = """
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :lsm)
    end

    test "struct_ops allows any context (nil mapping)" do
      source = """
      (defn handler [ctx :PtRegs] :u64
        (. ctx :rdi))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :struct_ops)
    end
  end

  describe "no annotation skips validation" do
    test "nil prog_type with any context passes" do
      source = """
      (defn handler [ctx :XdpMd] :u32
        (. ctx :data))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, nil)
    end

    test "default check/2 with any context passes" do
      source = """
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps)
    end
  end

  describe "new context types work" do
    test "cgroup_sock with BpfSock parameter" do
      source = """
      (defn handler [ctx :BpfSock] :u32
        (. ctx :family))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :cgroup_sock)
    end

    test "cgroup_sock_addr with BpfSockAddr parameter" do
      source = """
      (defn handler [ctx :BpfSockAddr] :u32
        (. ctx :user_family))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :cgroup_sock_addr)
    end

    test "sk_msg with BpfSkMsg parameter" do
      source = """
      (defn handler [ctx :BpfSkMsg] :u32
        (. ctx :family))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :sk_msg)
    end

    test "flow_dissector with BpfFlowKeys parameter" do
      source = """
      (defn handler [ctx :BpfFlowKeys] :u16
        (. ctx :sport))
      """
      {ast, maps} = prepare(source)
      assert {:ok, _, _} = BpfTypeChecker.check(ast, maps, :flow_dissector)
    end
  end

  describe "end-to-end via compile_source" do
    test "correct context compiles successfully" do
      source = """
      (program :xdp)
      (defn handler [ctx :XdpMd] :u32
        (. ctx :data))
      """
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "wrong context is rejected" do
      source = """
      (program :xdp)
      (defn handler [ctx :SkBuff] :u32
        (. ctx :len))
      """
      assert {:error, err} = VaistoBpf.compile_source(source)
      assert err.message =~ "wrong context type for :xdp"
    end
  end
end
