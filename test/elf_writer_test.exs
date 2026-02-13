defmodule VaistoBpf.ElfWriterTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.ElfWriter
  alias VaistoBpf.Types

  import Bitwise

  # ============================================================================
  # ELF Parsing Helpers
  # ============================================================================

  defp parse_elf_header(<<
         0x7F, ?E, ?L, ?F,
         ei_class::8,
         ei_data::8,
         ei_version::8,
         _ei_osabi::8,
         _pad::64,
         e_type::little-16,
         e_machine::little-16,
         e_version::little-32,
         _e_entry::little-64,
         _e_phoff::little-64,
         e_shoff::little-64,
         _e_flags::little-32,
         e_ehsize::little-16,
         _e_phentsize::little-16,
         _e_phnum::little-16,
         e_shentsize::little-16,
         e_shnum::little-16,
         e_shstrndx::little-16,
         _rest::binary
       >>) do
    %{
      ei_class: ei_class,
      ei_data: ei_data,
      ei_version: ei_version,
      e_type: e_type,
      e_machine: e_machine,
      e_version: e_version,
      e_shoff: e_shoff,
      e_ehsize: e_ehsize,
      e_shentsize: e_shentsize,
      e_shnum: e_shnum,
      e_shstrndx: e_shstrndx
    }
  end

  defp parse_section_header(<<
         sh_name::little-32,
         sh_type::little-32,
         sh_flags::little-64,
         _sh_addr::little-64,
         sh_offset::little-64,
         sh_size::little-64,
         sh_link::little-32,
         sh_info::little-32,
         sh_addralign::little-64,
         sh_entsize::little-64
       >>) do
    %{
      sh_name: sh_name,
      sh_type: sh_type,
      sh_flags: sh_flags,
      sh_offset: sh_offset,
      sh_size: sh_size,
      sh_link: sh_link,
      sh_info: sh_info,
      sh_addralign: sh_addralign,
      sh_entsize: sh_entsize
    }
  end

  defp get_section_headers(elf) do
    header = parse_elf_header(elf)

    for i <- 0..(header.e_shnum - 1) do
      start = header.e_shoff + i * header.e_shentsize
      shdr_bin = binary_part(elf, start, header.e_shentsize)
      parse_section_header(shdr_bin)
    end
  end

  defp extract_section_data(elf, section_index) do
    shdrs = get_section_headers(elf)
    shdr = Enum.at(shdrs, section_index)
    binary_part(elf, shdr.sh_offset, shdr.sh_size)
  end

  defp get_section_name(elf, shdr) do
    header = parse_elf_header(elf)
    shdrs = get_section_headers(elf)
    shstrtab_shdr = Enum.at(shdrs, header.e_shstrndx)
    shstrtab = binary_part(elf, shstrtab_shdr.sh_offset, shstrtab_shdr.sh_size)
    extract_cstring(shstrtab, shdr.sh_name)
  end

  defp extract_cstring(bin, offset) do
    <<_::binary-size(offset), rest::binary>> = bin
    [str | _] = :binary.split(rest, <<0>>)
    str
  end

  defp parse_sym_entry(<<
         st_name::little-32,
         st_info::8,
         _st_other::8,
         st_shndx::little-16,
         st_value::little-64,
         st_size::little-64
       >>) do
    %{
      st_name: st_name,
      st_info: st_info,
      st_bind: st_info >>> 4,
      st_type: st_info &&& 0xF,
      st_shndx: st_shndx,
      st_value: st_value,
      st_size: st_size
    }
  end

  # ============================================================================
  # Sample Instructions
  # ============================================================================

  defp sample_instructions do
    # mov r0, 42; exit — a trivial BPF program
    [
      Types.encode(Types.mov64_imm(0, 42)),
      Types.encode(Types.exit_insn())
    ]
  end

  # ============================================================================
  # Tests: ELF Header
  # ============================================================================

  describe "ELF header" do
    test "magic bytes, class, endianness" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.ei_class == 2, "ELFCLASS64"
      assert header.ei_data == 1, "ELFDATA2LSB (little-endian)"
      assert header.ei_version == 1, "EV_CURRENT"
    end

    test "e_type is ET_REL (relocatable)" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.e_type == 1
    end

    test "e_machine is EM_BPF (247)" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.e_machine == 247
    end

    test "header is 64 bytes" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.e_ehsize == 64
    end

    test "section header entry size is 64 bytes" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.e_shentsize == 64
    end

    test "6 section headers" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.e_shnum == 6
    end

    test "shstrndx is 5 (last section)" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      assert header.e_shstrndx == 5
    end
  end

  # ============================================================================
  # Tests: Section Content
  # ============================================================================

  describe "program section (.text)" do
    test "contains exact concatenated instruction bytes" do
      instructions = sample_instructions()
      {:ok, elf} = ElfWriter.to_elf(instructions)

      text_data = extract_section_data(elf, 1)
      expected = IO.iodata_to_binary(instructions)

      assert text_data == expected
    end

    test "section is named .text by default" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      name = get_section_name(elf, Enum.at(shdrs, 1))

      assert name == ".text"
    end

    test "has SHF_ALLOC | SHF_EXECINSTR flags" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      text_shdr = Enum.at(shdrs, 1)

      assert text_shdr.sh_flags == (0x2 ||| 0x4)
    end

    test "alignment is 8 (instruction size)" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      text_shdr = Enum.at(shdrs, 1)

      assert text_shdr.sh_addralign == 8
    end
  end

  describe "license section" do
    test "contains GPL with null terminator" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      license_data = extract_section_data(elf, 2)

      assert license_data == <<"GPL", 0>>
    end

    test "section is named .license" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      name = get_section_name(elf, Enum.at(shdrs, 2))

      assert name == ".license"
    end

    test "custom license string" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions(), license: "Dual BSD/GPL")
      license_data = extract_section_data(elf, 2)

      assert license_data == <<"Dual BSD/GPL", 0>>
    end
  end

  # ============================================================================
  # Tests: Symbol Table
  # ============================================================================

  describe "symbol table" do
    test "contains null symbol and one FUNC symbol" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      symtab_data = extract_section_data(elf, 3)

      # 2 entries × 24 bytes
      assert byte_size(symtab_data) == 48

      # First entry: null symbol
      null_sym = parse_sym_entry(binary_part(symtab_data, 0, 24))
      assert null_sym.st_name == 0
      assert null_sym.st_info == 0

      # Second entry: function symbol
      func_sym = parse_sym_entry(binary_part(symtab_data, 24, 24))
      assert func_sym.st_type == 2, "STT_FUNC"
      assert func_sym.st_bind == 1, "STB_GLOBAL"
      assert func_sym.st_shndx == 1, "points to .text section"
    end

    test "function symbol size matches text section" do
      instructions = sample_instructions()
      {:ok, elf} = ElfWriter.to_elf(instructions)
      symtab_data = extract_section_data(elf, 3)
      func_sym = parse_sym_entry(binary_part(symtab_data, 24, 24))

      expected_size = length(instructions) * 8
      assert func_sym.st_size == expected_size
    end

    test "symtab sh_link points to strtab (index 4)" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      symtab_shdr = Enum.at(shdrs, 3)

      assert symtab_shdr.sh_link == 4
    end

    test "symtab sh_entsize is 24" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      symtab_shdr = Enum.at(shdrs, 3)

      assert symtab_shdr.sh_entsize == 24
    end
  end

  describe "string tables" do
    test "strtab contains function name" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      strtab_data = extract_section_data(elf, 4)

      # Starts with null byte, then "main\0"
      assert strtab_data == <<0, "main", 0>>
    end

    test "shstrtab contains all section names" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shstrtab_data = extract_section_data(elf, 5)

      assert String.contains?(shstrtab_data, ".text")
      assert String.contains?(shstrtab_data, ".license")
      assert String.contains?(shstrtab_data, ".symtab")
      assert String.contains?(shstrtab_data, ".strtab")
      assert String.contains?(shstrtab_data, ".shstrtab")
    end
  end

  # ============================================================================
  # Tests: Options
  # ============================================================================

  describe "custom options" do
    test "custom section name" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions(), section: "kprobe/my_func")
      shdrs = get_section_headers(elf)
      name = get_section_name(elf, Enum.at(shdrs, 1))

      assert name == "kprobe/my_func"
    end

    test "custom function name appears in strtab" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions(), function_name: "my_prog")
      strtab_data = extract_section_data(elf, 4)

      assert strtab_data == <<0, "my_prog", 0>>
    end
  end

  # ============================================================================
  # Tests: Edge Cases
  # ============================================================================

  describe "edge cases" do
    test "empty instruction list produces valid ELF" do
      {:ok, elf} = ElfWriter.to_elf([])
      header = parse_elf_header(elf)

      assert header.e_machine == 247
      assert header.e_shnum == 6

      # .text section has zero size
      shdrs = get_section_headers(elf)
      text_shdr = Enum.at(shdrs, 1)
      assert text_shdr.sh_size == 0
    end

    test "null section is first and all-zeros" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      shdrs = get_section_headers(elf)
      null_shdr = Enum.at(shdrs, 0)

      assert null_shdr.sh_type == 0
      assert null_shdr.sh_offset == 0
      assert null_shdr.sh_size == 0
    end

    test "many instructions" do
      # 100 MOV instructions
      instructions = for i <- 1..100, do: Types.encode(Types.mov64_imm(0, i))
      {:ok, elf} = ElfWriter.to_elf(instructions)
      header = parse_elf_header(elf)

      assert header.e_machine == 247

      text_data = extract_section_data(elf, 1)
      assert byte_size(text_data) == 100 * 8
    end

    test "section header table is at the end" do
      {:ok, elf} = ElfWriter.to_elf(sample_instructions())
      header = parse_elf_header(elf)

      # sh_offset + 6 section headers × 64 bytes should equal total file size
      expected_end = header.e_shoff + header.e_shnum * header.e_shentsize
      assert expected_end == byte_size(elf)
    end
  end

  # ============================================================================
  # Tests: write_file/3
  # ============================================================================

  describe "write_file/3" do
    test "writes valid ELF to disk" do
      path = Path.join(System.tmp_dir!(), "vaisto_bpf_test_#{:rand.uniform(10000)}.o")

      try do
        :ok = ElfWriter.write_file(sample_instructions(), path)
        {:ok, elf} = File.read(path)
        header = parse_elf_header(elf)

        assert header.e_machine == 247
        assert header.e_type == 1
      after
        File.rm(path)
      end
    end
  end
end
