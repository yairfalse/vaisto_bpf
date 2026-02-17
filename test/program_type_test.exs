defmodule VaistoBpf.ProgramTypeTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Preprocessor

  describe "extract_program/1" do
    test "returns nil when no annotation present" do
      {cleaned, section, prog_type} = Preprocessor.extract_program("(defn foo [] :u64 0)")
      assert section == nil
      assert prog_type == nil
      assert cleaned == "(defn foo [] :u64 0)"
    end

    test "extracts kprobe with function name" do
      source = ~s|(program :kprobe "do_sys_open")\n(defn handler [] :u64 0)|
      {cleaned, section, prog_type} = Preprocessor.extract_program(source)
      assert section == "kprobe/do_sys_open"
      assert prog_type == :kprobe
      refute String.contains?(cleaned, "program")
    end

    test "extracts xdp without attach point" do
      source = "(program :xdp)\n(defn handler [] :u64 0)"
      {cleaned, section, prog_type} = Preprocessor.extract_program(source)
      assert section == "xdp"
      assert prog_type == :xdp
      refute String.contains?(cleaned, "program")
    end

    test "extracts tracepoint with nested path" do
      source = ~s|(program :tracepoint "syscalls/sys_enter_open")|
      {_cleaned, section, prog_type} = Preprocessor.extract_program(source)
      assert section == "tracepoint/syscalls/sys_enter_open"
      assert prog_type == :tracepoint
    end

    test "preserves surrounding source code" do
      source = "(defn before [] :u64 1)\n(program :xdp)\n(defn after [] :u64 2)"
      {cleaned, section, prog_type} = Preprocessor.extract_program(source)
      assert section == "xdp"
      assert prog_type == :xdp
      assert String.contains?(cleaned, "before")
      assert String.contains?(cleaned, "after")
    end

    test "rejects unsupported program type" do
      assert_raise RuntimeError, ~r/unsupported program type/, fn ->
        Preprocessor.extract_program("(program :invalid)")
      end
    end

    test "extracts all supported types" do
      for type <- ~w(kprobe kretprobe uprobe uretprobe xdp tc
                     tracepoint raw_tracepoint socket_filter cgroup_skb) do
        {_cleaned, section, prog_type} = Preprocessor.extract_program("(program :#{type})")
        assert section == type
        assert prog_type == String.to_atom(type)
      end
    end
  end

  describe "ELF section name" do
    test "compile_source_to_elf uses program annotation as section name" do
      source = """
      (program :xdp)
      (defn handler [] :u64 0)
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
      # The ELF should contain the section name "xdp"
      assert :binary.match(elf, "xdp") != :nomatch
    end

    test "compile_source_to_elf with kprobe section" do
      source = """
      (program :kprobe "do_sys_open")
      (defn handler [] :u64 0)
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert :binary.match(elf, "kprobe/do_sys_open") != :nomatch
    end

    test "explicit :section option overrides program annotation" do
      source = """
      (program :xdp)
      (defn handler [] :u64 0)
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source, section: "custom")
      assert :binary.match(elf, "custom") != :nomatch
    end
  end
end
