defmodule VaistoBpf.ExamplesTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Compile-only tests for example programs.

  Verifies that each example produces a valid ELF binary with the
  expected sections (program text, maps, BTF, BTF.ext, etc.).
  """

  # ============================================================================
  # Helpers
  # ============================================================================

  defp compile_example(filename) do
    path = Path.join([File.cwd!(), "examples", filename])
    source = File.read!(path)
    VaistoBpf.compile_source_to_elf(source)
  end

  defp find_sections(elf) do
    <<_ident::binary-size(16), _type::little-16, _machine::little-16,
      _version::little-32, _entry::little-64, _phoff::little-64,
      shoff::little-64, _flags::little-32, _ehsize::little-16,
      _phentsize::little-16, _phnum::little-16, shentsize::little-16,
      shnum::little-16, shstrndx::little-16, _rest::binary>> = elf

    shdrs =
      for i <- 0..(shnum - 1) do
        offset = shoff + i * shentsize
        <<_::binary-size(offset), shdr::binary-size(shentsize), _::binary>> = elf
        parse_shdr(shdr)
      end

    shstrtab_hdr = Enum.at(shdrs, shstrndx)
    shstrtab = binary_part(elf, shstrtab_hdr.sh_offset, shstrtab_hdr.sh_size)

    Enum.map(shdrs, fn shdr ->
      name = read_string(shstrtab, shdr.sh_name)
      %{name: name, sh_size: shdr.sh_size}
    end)
  end

  defp parse_shdr(<<sh_name::little-32, _sh_type::little-32, _sh_flags::little-64,
                    _sh_addr::little-64, sh_offset::little-64, sh_size::little-64,
                    _sh_link::little-32, _sh_info::little-32, _sh_addralign::little-64,
                    _sh_entsize::little-64>>) do
    %{sh_name: sh_name, sh_offset: sh_offset, sh_size: sh_size}
  end

  defp read_string(strtab, offset) do
    rest = binary_part(strtab, offset, byte_size(strtab) - offset)
    [name | _] = :binary.split(rest, <<0>>)
    name
  end

  defp section_names(elf) do
    elf |> find_sections() |> Enum.map(& &1.name)
  end

  # ============================================================================
  # XDP Packet Counter
  # ============================================================================

  describe "xdp_packet_counter" do
    test "compiles to valid ELF" do
      assert {:ok, elf} = compile_example("xdp_packet_counter.vaisto")
      assert is_binary(elf)
      assert byte_size(elf) > 0
    end

    test "has program text section" do
      {:ok, elf} = compile_example("xdp_packet_counter.vaisto")
      names = section_names(elf)
      assert "xdp" in names or ".text" in names
    end

    test "has maps section" do
      {:ok, elf} = compile_example("xdp_packet_counter.vaisto")
      names = section_names(elf)
      assert ".maps" in names
    end

    test "has BTF section" do
      {:ok, elf} = compile_example("xdp_packet_counter.vaisto")
      names = section_names(elf)
      assert ".BTF" in names
    end

    test "has BTF.ext section" do
      {:ok, elf} = compile_example("xdp_packet_counter.vaisto")
      names = section_names(elf)
      assert ".BTF.ext" in names
    end

    test "program section has instructions" do
      {:ok, elf} = compile_example("xdp_packet_counter.vaisto")
      sections = find_sections(elf)
      prog = Enum.find(sections, fn s -> s.name == "xdp" or s.name == ".text" end)
      assert prog != nil
      # BPF instructions are 8 bytes each, minimum a few instructions
      assert prog.sh_size >= 24
      assert rem(prog.sh_size, 8) == 0
    end
  end

  # ============================================================================
  # Kprobe Tracer
  # ============================================================================

  describe "kprobe_tracer" do
    test "compiles to valid ELF" do
      assert {:ok, elf} = compile_example("kprobe_tracer.vaisto")
      assert byte_size(elf) > 0
    end

    test "has ringbuf map section" do
      {:ok, elf} = compile_example("kprobe_tracer.vaisto")
      names = section_names(elf)
      assert ".maps" in names
    end

    test "has BTF and BTF.ext sections" do
      {:ok, elf} = compile_example("kprobe_tracer.vaisto")
      names = section_names(elf)
      assert ".BTF" in names
      assert ".BTF.ext" in names
    end

    test "program section name matches kprobe attach point" do
      {:ok, elf} = compile_example("kprobe_tracer.vaisto")
      names = section_names(elf)
      # kprobe programs get section name "kprobe/sys_execve" or similar
      assert Enum.any?(names, fn n -> String.starts_with?(n, "kprobe") end)
    end
  end

  # ============================================================================
  # Cgroup SKB Filter
  # ============================================================================

  describe "cgroup_skb_filter" do
    test "compiles to valid ELF" do
      assert {:ok, elf} = compile_example("cgroup_skb_filter.vaisto")
      assert byte_size(elf) > 0
    end

    test "has map and BTF sections" do
      {:ok, elf} = compile_example("cgroup_skb_filter.vaisto")
      names = section_names(elf)
      assert ".maps" in names
      assert ".BTF" in names
    end

    test "multi-function program has BTF.ext" do
      {:ok, elf} = compile_example("cgroup_skb_filter.vaisto")
      names = section_names(elf)
      assert ".BTF.ext" in names
    end

    test "program section is large enough for two functions" do
      {:ok, elf} = compile_example("cgroup_skb_filter.vaisto")
      sections = find_sections(elf)
      prog = Enum.find(sections, fn s ->
        s.name == "cgroup_skb" or s.name == ".text"
      end)
      assert prog != nil
      # Two functions should produce at least ~10 instructions
      assert prog.sh_size >= 80
    end
  end

  # ============================================================================
  # Cross-cutting: all examples
  # ============================================================================

  describe "all examples" do
    test "every .vaisto file in examples/ compiles" do
      examples_dir = Path.join(File.cwd!(), "examples")

      files =
        examples_dir
        |> File.ls!()
        |> Enum.filter(&String.ends_with?(&1, ".vaisto"))

      assert length(files) >= 3, "expected at least 3 example files"

      for file <- files do
        source = File.read!(Path.join(examples_dir, file))

        assert {:ok, _elf} = VaistoBpf.compile_source_to_elf(source),
               "#{file} failed to compile"
      end
    end

    test "all examples produce valid ELF magic" do
      examples_dir = Path.join(File.cwd!(), "examples")

      for file <- File.ls!(examples_dir), String.ends_with?(file, ".vaisto") do
        source = File.read!(Path.join(examples_dir, file))
        {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
        # ELF magic: 0x7f ELF
        assert <<0x7F, "ELF", _rest::binary>> = elf
      end
    end
  end
end
