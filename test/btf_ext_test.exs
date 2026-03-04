defmodule VaistoBpf.BTFExtTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.BTFExt

  import Bitwise

  # ============================================================================
  # Helpers
  # ============================================================================

  defp parse_btf_ext_header(<<
         magic::little-16,
         version::8,
         _flags::8,
         hdr_len::little-32,
         func_info_off::little-32,
         func_info_len::little-32,
         line_info_off::little-32,
         line_info_len::little-32,
         core_relo_off::little-32,
         core_relo_len::little-32,
         rest::binary
       >>) do
    %{
      magic: magic,
      version: version,
      hdr_len: hdr_len,
      func_info_off: func_info_off,
      func_info_len: func_info_len,
      line_info_off: line_info_off,
      line_info_len: line_info_len,
      core_relo_off: core_relo_off,
      core_relo_len: core_relo_len,
      rest: rest
    }
  end

  # ============================================================================
  # Tests: Header
  # ============================================================================

  describe "BTF.ext header" do
    test "magic is 0xEB9F" do
      bin = BTFExt.encode(".text", [{0, 1}], 0)
      header = parse_btf_ext_header(bin)
      assert header.magic == 0xEB9F
    end

    test "version is 1" do
      bin = BTFExt.encode(".text", [{0, 1}], 0)
      header = parse_btf_ext_header(bin)
      assert header.version == 1
    end

    test "header length is 32" do
      bin = BTFExt.encode(".text", [{0, 1}], 0)
      header = parse_btf_ext_header(bin)
      assert header.hdr_len == 32
    end

    test "func_info_len covers section header + records" do
      # 1 record: sec_header(12) + 1*rec(8) = 20 bytes
      bin = BTFExt.encode(".text", [{0, 1}], 0)
      header = parse_btf_ext_header(bin)
      assert header.func_info_len == 20
    end

    test "line_info_len is 0" do
      bin = BTFExt.encode(".text", [{0, 1}], 0)
      header = parse_btf_ext_header(bin)
      assert header.line_info_len == 0
    end
  end

  # ============================================================================
  # Tests: Func Info Records
  # ============================================================================

  describe "func_info records" do
    test "single record encodes correctly" do
      bin = BTFExt.encode(".text", [{0, 42}], 5)
      header = parse_btf_ext_header(bin)

      # Skip to func_info section
      func_info = binary_part(bin, header.hdr_len + header.func_info_off, header.func_info_len)

      # Parse section header: sec_name_off(4) + num_info(4) + rec_size(4)
      <<sec_name_off::little-32, num_info::little-32, rec_size::little-32,
        insn_off::little-32, type_id::little-32>> = func_info

      assert sec_name_off == 5
      assert num_info == 1
      assert rec_size == 8
      assert insn_off == 0
      assert type_id == 42
    end

    test "multiple records sorted by offset" do
      func_infos = [{0, 10}, {64, 20}, {128, 30}]
      bin = BTFExt.encode(".text", func_infos, 0)
      header = parse_btf_ext_header(bin)

      func_info = binary_part(bin, header.hdr_len + header.func_info_off, header.func_info_len)

      # sec_header (12) + 3 records (24)
      assert byte_size(func_info) == 36

      <<_sec_hdr::binary-size(12),
        off1::little-32, id1::little-32,
        off2::little-32, id2::little-32,
        off3::little-32, id3::little-32>> = func_info

      assert {off1, id1} == {0, 10}
      assert {off2, id2} == {64, 20}
      assert {off3, id3} == {128, 30}
    end
  end

  # ============================================================================
  # Tests: build_func_infos
  # ============================================================================

  describe "build_func_infos" do
    test "builds from func_offsets and func_type_ids" do
      func_offsets = %{helper: 10, worker: 20}
      func_type_ids = %{helper: 5, worker: 7}

      infos = BTFExt.build_func_infos(func_offsets, func_type_ids)

      assert infos == [{80, 5}, {160, 7}]  # 10*8, 20*8
    end

    test "includes entry function at offset 0" do
      func_offsets = %{helper: 10}
      func_type_ids = %{main: 3, helper: 5}

      infos = BTFExt.build_func_infos(func_offsets, func_type_ids, 3)

      assert hd(infos) == {0, 3}
      assert length(infos) == 2
    end

    test "skips functions without BTF type IDs" do
      func_offsets = %{helper: 10, unknown: 20}
      func_type_ids = %{helper: 5}

      infos = BTFExt.build_func_infos(func_offsets, func_type_ids)

      assert length(infos) == 1
      assert hd(infos) == {80, 5}
    end

    test "returns empty when no matching functions" do
      infos = BTFExt.build_func_infos(%{}, %{})
      assert infos == []
    end
  end

  # ============================================================================
  # Tests: ELF Integration
  # ============================================================================

  describe "ELF integration" do
    test "program with functions produces .BTF.ext section" do
      source = """
      (defn helper [x :u64] :u64 (+ x 1))
      (defn main [y :u64] :u64 (helper y))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      # Find .BTF.ext section
      sections = find_sections(elf)
      btf_ext_idx = Enum.find_index(sections, fn s -> s.name == ".BTF.ext" end)
      assert btf_ext_idx != nil, "should have .BTF.ext section"

      # Verify it has valid BTF.ext magic
      btf_ext = Enum.at(sections, btf_ext_idx)
      assert <<0x9F, 0xEB, _rest::binary>> = btf_ext.data
    end

    test "program with maps and functions has both .BTF and .BTF.ext" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn lookup [key :u64] :u64
        (match (bpf/map_lookup_elem counters key)
          [(Some v) (bpf/load_u64 v 0)]
          [(None) 0]))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)

      sections = find_sections(elf)
      btf_names = Enum.map(sections, & &1.name)
      assert ".BTF" in btf_names
      assert ".BTF.ext" in btf_names
    end
  end

  # ============================================================================
  # Tests: CO-RE Relocations
  # ============================================================================

  describe "CO-RE relocations" do
    test "build_core_relo_entries creates entries from assembler metadata" do
      btf = VaistoBpf.BTF.new()
      # Add a struct type
      {_struct_id, btf} = VaistoBpf.BTF.add_struct(btf, "xdp_md", 20, [
        {"data", 0, 0},
        {"data_end", 0, 32},
        {"data_meta", 0, 64}
      ])

      core_relos = [
        %{insn_off: 0, record: :xdp_md, field: :data, field_index: 0},
        %{insn_off: 8, record: :xdp_md, field: :data_end, field_index: 1}
      ]

      {entries, _btf} = BTFExt.build_core_relo_entries(core_relos, btf)

      assert length(entries) == 2
      # Each entry: {insn_off, type_id, access_str_off, kind=0}
      {off1, tid1, _str1, kind1} = hd(entries)
      assert off1 == 0
      assert tid1 > 0  # struct type ID
      assert kind1 == 0  # BPF_CORE_FIELD_BYTE_OFFSET
    end

    test "core_relo_len is 0 when no relocations" do
      bin = BTFExt.encode(".text", [{0, 1}], 0, [])
      header = parse_btf_ext_header(bin)
      assert header.core_relo_len == 0
    end
  end

  # ============================================================================
  # ELF Parsing Helpers
  # ============================================================================

  defp find_sections(elf) do
    <<_ident::binary-size(16), _type::little-16, _machine::little-16,
      _version::little-32, _entry::little-64, _phoff::little-64,
      shoff::little-64, _flags::little-32, _ehsize::little-16,
      _phentsize::little-16, _phnum::little-16, shentsize::little-16,
      shnum::little-16, shstrndx::little-16, _rest::binary>> = elf

    # Parse section headers
    shdrs =
      for i <- 0..(shnum - 1) do
        offset = shoff + i * shentsize
        <<_::binary-size(offset), shdr::binary-size(shentsize), _::binary>> = elf
        parse_shdr(shdr)
      end

    # Get shstrtab
    shstrtab_hdr = Enum.at(shdrs, shstrndx)
    shstrtab = binary_part(elf, shstrtab_hdr.sh_offset, shstrtab_hdr.sh_size)

    # Assign names
    Enum.map(shdrs, fn shdr ->
      name = read_string(shstrtab, shdr.sh_name)
      data = if shdr.sh_size > 0, do: binary_part(elf, shdr.sh_offset, shdr.sh_size), else: <<>>
      %{name: name, data: data, sh_type: shdr.sh_type, sh_offset: shdr.sh_offset, sh_size: shdr.sh_size}
    end)
  end

  defp parse_shdr(<<sh_name::little-32, sh_type::little-32, _sh_flags::little-64,
                    _sh_addr::little-64, sh_offset::little-64, sh_size::little-64,
                    _sh_link::little-32, _sh_info::little-32, _sh_addralign::little-64,
                    _sh_entsize::little-64>>) do
    %{sh_name: sh_name, sh_type: sh_type, sh_offset: sh_offset, sh_size: sh_size}
  end

  defp read_string(strtab, offset) do
    rest = binary_part(strtab, offset, byte_size(strtab) - offset)
    [name | _] = :binary.split(rest, <<0>>)
    name
  end
end
