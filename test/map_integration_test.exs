defmodule VaistoBpf.MapIntegrationTest do
  use ExUnit.Case, async: true

  import Bitwise

  # ============================================================================
  # ELF Parsing Helpers (same as elf_writer_test.exs)
  # ============================================================================

  defp parse_elf_header(<<
         0x7F, ?E, ?L, ?F,
         _ei_class::8, _ei_data::8, _ei_version::8, _ei_osabi::8,
         _pad::64,
         _e_type::little-16, e_machine::little-16, _e_version::little-32,
         _e_entry::little-64, _e_phoff::little-64,
         e_shoff::little-64, _e_flags::little-32,
         _e_ehsize::little-16, _e_phentsize::little-16, _e_phnum::little-16,
         e_shentsize::little-16, e_shnum::little-16, e_shstrndx::little-16,
         _rest::binary
       >>) do
    %{e_machine: e_machine, e_shoff: e_shoff, e_shentsize: e_shentsize,
      e_shnum: e_shnum, e_shstrndx: e_shstrndx}
  end

  defp parse_section_header(<<
         sh_name::little-32, sh_type::little-32, sh_flags::little-64,
         _sh_addr::little-64, sh_offset::little-64, sh_size::little-64,
         sh_link::little-32, sh_info::little-32,
         sh_addralign::little-64, sh_entsize::little-64
       >>) do
    %{sh_name: sh_name, sh_type: sh_type, sh_flags: sh_flags,
      sh_offset: sh_offset, sh_size: sh_size, sh_link: sh_link,
      sh_info: sh_info, sh_addralign: sh_addralign, sh_entsize: sh_entsize}
  end

  defp get_section_headers(elf) do
    header = parse_elf_header(elf)
    for i <- 0..(header.e_shnum - 1) do
      start = header.e_shoff + i * header.e_shentsize
      parse_section_header(binary_part(elf, start, header.e_shentsize))
    end
  end

  defp extract_section_data(elf, section_index) do
    shdrs = get_section_headers(elf)
    shdr = Enum.at(shdrs, section_index)
    if shdr.sh_size == 0, do: <<>>, else: binary_part(elf, shdr.sh_offset, shdr.sh_size)
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
         st_name::little-32, st_info::8, _st_other::8,
         st_shndx::little-16, st_value::little-64, st_size::little-64
       >>) do
    %{st_name: st_name, st_info: st_info, st_bind: st_info >>> 4,
      st_type: st_info &&& 0xF, st_shndx: st_shndx, st_value: st_value,
      st_size: st_size}
  end

  defp find_section_by_name(elf, name) do
    shdrs = get_section_headers(elf)
    Enum.find_index(shdrs, fn shdr -> get_section_name(elf, shdr) == name end)
  end

  # ============================================================================
  # Source Compilation Tests
  # ============================================================================

  describe "compile_source/1 with maps" do
    test "compiles defmap + function referencing the map" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      """
      assert {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "map without function usage still compiles" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defn identity [x :u64] :u64 x)
      """
      assert {:ok, _instructions} = VaistoBpf.compile_source(source)
    end

    test "no maps still works (backward compatible)" do
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      assert {:ok, _instructions} = VaistoBpf.compile_source(source)
    end
  end

  # ============================================================================
  # ELF Output Structure Tests
  # ============================================================================

  describe "compile_source_to_elf/2 with maps" do
    test "ELF has 9 sections when maps present" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      header = parse_elf_header(elf)

      assert header.e_shnum == 9
      assert header.e_machine == 247
    end

    test "ELF has 6 sections when no maps" do
      source = "(defn add [x :u64 y :u64] :u64 (+ x y))"
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      header = parse_elf_header(elf)

      assert header.e_shnum == 6
    end

    test "contains .maps section" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defn identity [x :u64] :u64 x)
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      idx = find_section_by_name(elf, ".maps")
      assert idx != nil, "should have .maps section"

      maps_data = extract_section_data(elf, idx)
      # 16 bytes per map (4 u32 fields)
      assert byte_size(maps_data) == 16
    end

    test "contains .BTF section with correct magic" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defn identity [x :u64] :u64 x)
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      idx = find_section_by_name(elf, ".BTF")
      assert idx != nil, "should have .BTF section"

      btf_data = extract_section_data(elf, idx)
      <<magic::little-16, _rest::binary>> = btf_data
      assert magic == 0xEB9F, "BTF magic should be 0xEB9F"
    end

    test "contains .rel.text section" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      idx = find_section_by_name(elf, ".rel.text")
      assert idx != nil, "should have .rel.text section"

      rel_data = extract_section_data(elf, idx)
      # At least one relocation entry (16 bytes each)
      assert byte_size(rel_data) >= 16
      assert rem(byte_size(rel_data), 16) == 0
    end

    test ".rel.text section header links to symtab and .text" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      idx = find_section_by_name(elf, ".rel.text")
      shdrs = get_section_headers(elf)
      rel_shdr = Enum.at(shdrs, idx)

      # sh_link points to .symtab (index 6)
      assert rel_shdr.sh_link == 6
      # sh_info points to .text (index 1)
      assert rel_shdr.sh_info == 1
      # entsize is 16 (Elf64_Rel)
      assert rel_shdr.sh_entsize == 16
    end
  end

  # ============================================================================
  # LD_IMM64 Instruction Tests
  # ============================================================================

  describe "LD_IMM64 in .text" do
    test "map reference produces 16-byte wide instruction" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)

      # Instructions is a flat list of 8-byte binaries
      # LD_IMM64 shows up as two consecutive 8-byte entries
      # Find the LD_IMM64: opcode 0x18, src=1
      ld_imm64_count =
        instructions
        |> Enum.count(fn <<opcode::8, regs::8, _rest::binary>> ->
          opcode == 0x18 and (regs >>> 4) == 1
        end)

      assert ld_imm64_count >= 1, "should have at least one LD_IMM64 (pseudo-map-FD)"
    end
  end

  # ============================================================================
  # Symbol Table Tests
  # ============================================================================

  describe "map symbols in .symtab" do
    test "map symbol has STT_OBJECT type and STB_GLOBAL binding" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defn identity [x :u64] :u64 x)
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      symtab_idx = find_section_by_name(elf, ".symtab")
      symtab_data = extract_section_data(elf, symtab_idx)

      # Parse symbols: null(0) + func(1) + map(2)
      sym_count = div(byte_size(symtab_data), 24)
      assert sym_count == 3

      map_sym = parse_sym_entry(binary_part(symtab_data, 48, 24))
      assert map_sym.st_type == 1, "STT_OBJECT"
      assert map_sym.st_bind == 1, "STB_GLOBAL"
      assert map_sym.st_shndx == 3, "points to .maps section"
    end

    test "strtab contains map name" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defn identity [x :u64] :u64 x)
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      strtab_idx = find_section_by_name(elf, ".strtab")
      strtab_data = extract_section_data(elf, strtab_idx)

      assert String.contains?(strtab_data, "counters")
    end
  end

  # ============================================================================
  # Multiple Maps
  # ============================================================================

  describe "multiple maps" do
    test "two maps compile successfully" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defmap data :array :u32 :u32 256)
      (defn identity [x :u64] :u64 x)
      """
      assert {:ok, _instructions} = VaistoBpf.compile_source(source)
    end

    test "two maps produce correct ELF" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defmap data :array :u32 :u32 256)
      (defn identity [x :u64] :u64 x)
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      # .maps section: 2 × 16 bytes
      maps_idx = find_section_by_name(elf, ".maps")
      maps_data = extract_section_data(elf, maps_idx)
      assert byte_size(maps_data) == 32

      # Two map symbols + func + null = 4 symbols
      symtab_idx = find_section_by_name(elf, ".symtab")
      symtab_data = extract_section_data(elf, symtab_idx)
      assert div(byte_size(symtab_data), 24) == 4

      # Strtab contains both names
      strtab_idx = find_section_by_name(elf, ".strtab")
      strtab_data = extract_section_data(elf, strtab_idx)
      assert String.contains?(strtab_data, "counters")
      assert String.contains?(strtab_data, "data")
    end

    test "each map used in a separate function" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defmap data :array :u32 :u64 256)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup_counter [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      (defn lookup_data [key :u64] :u64
        (bpf/map_lookup_elem data key))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      # Should have at least 2 relocations (one per map reference)
      rel_idx = find_section_by_name(elf, ".rel.text")
      rel_data = extract_section_data(elf, rel_idx)
      assert byte_size(rel_data) >= 32, "should have at least 2 relocation entries"
    end
  end

  # ============================================================================
  # ELF Structural Integrity
  # ============================================================================

  describe "ELF structural integrity" do
    test "section header table is at the end" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (bpf/map_lookup_elem counters key))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      header = parse_elf_header(elf)

      expected_end = header.e_shoff + header.e_shnum * header.e_shentsize
      assert expected_end == byte_size(elf)
    end

    test "shstrtab contains all section names" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (defn identity [x :u64] :u64 x)
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      shstrtab_idx = parse_elf_header(elf).e_shstrndx
      shstrtab_data = extract_section_data(elf, shstrtab_idx)

      for name <- [".text", ".license", ".maps", ".BTF", ".rel.text", ".symtab", ".strtab", ".shstrtab"] do
        assert String.contains?(shstrtab_data, name), "shstrtab should contain #{name}"
      end
    end
  end
end
