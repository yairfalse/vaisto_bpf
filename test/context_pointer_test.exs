defmodule VaistoBpf.ContextPointerTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker

  defp type_check(source, opts \\ []) do
    {cleaned, _section, prog_type} = Preprocessor.extract_program(source)
    {cleaned, maps} = Preprocessor.extract_defmaps(cleaned)
    preprocessed = Preprocessor.preprocess_source(cleaned)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)
    BpfTypeChecker.check(normalized, maps, Keyword.merge([program_type: prog_type], opts))
  end

  defp compile_ir(source) do
    {cleaned, _section, prog_type} = Preprocessor.extract_program(source)
    {cleaned, maps} = Preprocessor.extract_defmaps(cleaned)
    preprocessed = Preprocessor.preprocess_source(cleaned)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)

    {:ok, _, typed_ast} = BpfTypeChecker.check(normalized, maps, program_type: prog_type)
    {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
    VaistoBpf.Emitter.emit(ast, maps)
  end

  describe "type checker — auto-promotion" do
    test "XdpMd param auto-promotes to {:ptr, :XdpMd}" do
      source = """
      (program :xdp)
      (defn handler [ctx :XdpMd] :u32 (. ctx :data))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "field access on auto-promoted context returns correct type" do
      source = """
      (program :xdp)
      (defn handler [ctx :XdpMd] :u32 (. ctx :data_end))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "nonexistent field on context is rejected" do
      source = """
      (program :xdp)
      (defn handler [ctx :XdpMd] :u32 (. ctx :nonexistent))
      """
      assert {:error, err} = type_check(source)
      assert err.message =~ "no field"
    end

    test "works without explicit deftype (built-in)" do
      source = """
      (program :xdp)
      (defn handler [ctx :XdpMd] :u32
        (if (> (. ctx :data_end) (. ctx :data)) 2 1))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "user deftype overrides built-in" do
      source = """
      (program :xdp)
      (deftype XdpMd [custom_field :u64])
      (defn handler [ctx :XdpMd] :u64 (. ctx :custom_field))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "SkBuff context works with tc program" do
      source = """
      (program :tc)
      (defn handler [skb :SkBuff] :u32 (. skb :len))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "PtRegs context works with kprobe program" do
      source = """
      (program :kprobe "sys_open")
      (defn handler [regs :PtRegs] :u64 (. regs :rdi))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "context type available even without program annotation" do
      # Built-in types are injected unconditionally
      source = """
      (defn handler [ctx :XdpMd] :u32 (. ctx :data))
      """
      assert {:ok, _, _} = type_check(source)
    end

    test "non-record params are not promoted" do
      source = """
      (program :xdp)
      (defn handler [x :u64] :u64 x)
      """
      assert {:ok, _, _} = type_check(source)
    end
  end

  describe "emitter — context field access" do
    test "XDP field access produces LDX_MEM with correct offsets" do
      source = """
      (program :xdp)
      (defn handler [ctx :XdpMd] :u32
        (if (> (. ctx :data_end) (. ctx :data)) 2 1))
      """
      {:ok, ir} = compile_ir(source)

      ldx_insns = Enum.filter(ir, &match?({:ldx_mem, _, _, _, _}, &1))

      # data is at offset 0, data_end at offset 4
      offsets = Enum.map(ldx_insns, fn {:ldx_mem, _size, _dst, _src, offset} -> offset end)
      assert 0 in offsets
      assert 4 in offsets
    end

    test "kprobe PtRegs field access produces correct offset" do
      source = """
      (program :kprobe "sys_open")
      (defn handler [regs :PtRegs] :u64 (. regs :rdi))
      """
      {:ok, ir} = compile_ir(source)

      # rdi is the 15th field (0-indexed: 14), all u64 → offset = 14 * 8 = 112
      ldx_insns = Enum.filter(ir, &match?({:ldx_mem, _, _, _, _}, &1))
      assert Enum.any?(ldx_insns, fn {:ldx_mem, _size, _dst, _src, offset} ->
        offset == 112
      end)
    end

    test "TC SkBuff field access at non-zero offset" do
      source = """
      (program :tc)
      (defn handler [skb :SkBuff] :u32 (. skb :mark))
      """
      {:ok, ir} = compile_ir(source)

      # mark is the 3rd field (index 2), all u32 → offset = 2 * 4 = 8
      ldx_insns = Enum.filter(ir, &match?({:ldx_mem, _, _, _, _}, &1))
      assert Enum.any?(ldx_insns, fn {:ldx_mem, _size, _dst, _src, offset} ->
        offset == 8
      end)
    end
  end

  describe "integration — compile_source" do
    test "XDP program compiles to bytecode" do
      source = """
      (program :xdp)
      (defn xdp_prog [ctx :XdpMd] :u32
        (if (> (. ctx :data_end) (. ctx :data)) 2 1))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "XDP program produces valid ELF with xdp section" do
      source = """
      (program :xdp)
      (defn xdp_prog [ctx :XdpMd] :u32
        (if (> (. ctx :data_end) (. ctx :data)) 2 1))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
      assert :binary.match(elf, "xdp") != :nomatch
    end

    test "TC program with SkBuff context compiles" do
      source = """
      (program :tc)
      (defn tc_prog [skb :SkBuff] :u32
        (if (> (. skb :len) 0) 0 2))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
    end

    test "kprobe with PtRegs context compiles" do
      source = """
      (program :kprobe "sys_open")
      (defn probe_handler [regs :PtRegs] :u64 (. regs :rdi))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
    end

    test "kprobe produces ELF with correct section" do
      source = """
      (program :kprobe "sys_open")
      (defn probe_handler [regs :PtRegs] :u64 (. regs :rdi))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert :binary.match(elf, "kprobe/sys_open") != :nomatch
    end

    test "context pointer with map and helper works" do
      source = """
      (program :xdp)
      (defmap counters :hash :u32 :u32 1024)
      (extern bpf:map_update_elem [:u64 :u32 :u32 :u64] :u64)

      (defn xdp_count [ctx :XdpMd] :u32
        (let [key (. ctx :ingress_ifindex)]
          (do
            (bpf/map_update_elem counters key key 0)
            2)))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
    end
  end
end
