defmodule VaistoBpf.ElfWriter do
  @moduledoc """
  Wraps BPF bytecode in a minimal ELF relocatable object file (.o).

  Produces the standard format expected by `bpftool prog load`, libbpf,
  and the `bpf()` syscall. The output contains:

  - `.text` (or custom) section with concatenated BPF instructions
  - `.license` section with null-terminated license string
  - `.symtab` with a FUNC symbol for the program entry point
  - `.strtab` and `.shstrtab` string tables

  When maps are present, the ELF additionally contains:
  - `.maps` section (zero-filled map variable data)
  - `.BTF` section (BPF Type Format metadata)
  - `.rel.text` section (relocations for map references)

  ## Usage

      {:ok, elf} = ElfWriter.to_elf(instructions)
      :ok = ElfWriter.write_file(instructions, "prog.o")

  ## Options

  - `:section` — program section name (default `".text"`)
  - `:license` — license string (default `"GPL"`)
  - `:function_name` — symbol name for the entry point (default `"main"`)
  - `:maps` — list of `%MapDef{}` structs (default `[]`)
  - `:relocations` — list of `{byte_offset, map_index}` tuples (default `[]`)
  """

  import Bitwise

  alias VaistoBpf.BTF

  # ============================================================================
  # ELF Constants
  # ============================================================================

  @elf_magic <<0x7F, ?E, ?L, ?F>>
  @elfclass64 2
  @elfdata2lsb 1
  @ev_current 1
  @elfosabi_none 0

  @et_rel 1
  @em_bpf 247

  # Section header types
  @sht_null 0
  @sht_progbits 1
  @sht_symtab 2
  @sht_strtab 3
  @sht_rel 9

  # Section flags
  @shf_alloc 0x2
  @shf_execinstr 0x4

  # Symbol binding/type
  @stb_global 1
  @stt_func 2
  @stt_object 1

  # Relocation types
  @r_bpf_64_64 1

  # ELF header size
  @elf_header_size 64
  # Section header entry size
  @shdr_size 64
  # Symbol table entry size (Elf64_Sym)
  @sym_entry_size 24
  # Relocation entry size (Elf64_Rel)
  @rel_entry_size 16

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Convert a list of 8-byte BPF instruction binaries to an ELF binary.

  Returns `{:ok, elf_binary}` or `{:error, %Vaisto.Error{}}`.
  """
  @spec to_elf([binary()], keyword()) :: {:ok, binary()} | {:error, Vaisto.Error.t()}
  def to_elf(instructions, opts \\ []) do
    maps = Keyword.get(opts, :maps, [])

    if maps == [] do
      to_elf_no_maps(instructions, opts)
    else
      to_elf_with_maps(instructions, opts)
    end
  end

  @doc """
  Compile BPF instructions to ELF and write to a file.
  """
  @spec write_file([binary()], Path.t(), keyword()) :: :ok | {:error, Vaisto.Error.t()}
  def write_file(instructions, path, opts \\ []) do
    case to_elf(instructions, opts) do
      {:ok, elf} -> File.write(path, elf)
      error -> error
    end
  end

  # ============================================================================
  # No Maps Path (6 sections — existing behavior)
  # ============================================================================

  defp to_elf_no_maps(instructions, opts) do
    section_name = Keyword.get(opts, :section, ".text")
    license = Keyword.get(opts, :license, "GPL")
    func_name = Keyword.get(opts, :function_name, "main")

    text_data = IO.iodata_to_binary(instructions)
    license_data = <<license::binary, 0>>

    {shstrtab, shstr_offsets} = build_shstrtab([section_name, ".license", ".symtab", ".strtab", ".shstrtab"])
    {strtab, str_name_offsets} = build_strtab([func_name])
    func_name_offset = Map.fetch!(str_name_offsets, func_name)
    symtab = build_symtab_no_maps(func_name_offset, byte_size(text_data))

    # Sections: null, text, license, symtab, strtab, shstrtab
    section_data = [text_data, license_data, symtab, strtab, shstrtab]
    {offsets, sh_offset} = calculate_layout(section_data)

    sh_num = 6
    shstrndx = 5

    elf_header = build_elf_header(sh_offset, sh_num, shstrndx)

    section_headers = build_section_headers_no_maps(
      section_data, offsets, shstr_offsets, section_name
    )

    elf = IO.iodata_to_binary([elf_header, section_data, section_headers])
    {:ok, elf}
  end

  # ============================================================================
  # Maps Path (9 sections)
  # ============================================================================

  # Section layout when maps present:
  #   0: null
  #   1: .text (program instructions)
  #   2: .license
  #   3: .maps (zero-filled map structs)
  #   4: .BTF (BTF metadata)
  #   5: .rel.text (relocations)
  #   6: .symtab
  #   7: .strtab
  #   8: .shstrtab

  defp to_elf_with_maps(instructions, opts) do
    section_name = Keyword.get(opts, :section, ".text")
    license = Keyword.get(opts, :license, "GPL")
    func_name = Keyword.get(opts, :function_name, "main")
    maps = Keyword.get(opts, :maps, [])
    relocations = Keyword.get(opts, :relocations, [])

    text_data = IO.iodata_to_binary(instructions)
    license_data = <<license::binary, 0>>

    # Generate BTF and .maps data
    {btf_data, maps_data} = BTF.encode_for_maps(maps)

    # Build relocations section
    rel_data = build_relocations(relocations, length(maps))

    # String tables need all section names
    section_names = [section_name, ".license", ".maps", ".BTF", ".rel" <> section_name,
                     ".symtab", ".strtab", ".shstrtab"]
    {shstrtab, shstr_offsets} = build_shstrtab(section_names)

    # Symbol names: func + map names
    map_names = Enum.map(maps, fn md -> Atom.to_string(md.name) end)
    {strtab, str_name_offsets} = build_strtab([func_name | map_names])
    func_name_offset = Map.fetch!(str_name_offsets, func_name)

    # Build symbol table: null + func + map symbols
    symtab = build_symtab_with_maps(func_name_offset, byte_size(text_data),
                                     maps, str_name_offsets, byte_size(maps_data))

    # Section data in order: text, license, maps, btf, rel, symtab, strtab, shstrtab
    section_data = [text_data, license_data, maps_data, btf_data, rel_data, symtab, strtab, shstrtab]
    {offsets, sh_offset} = calculate_layout(section_data)

    sh_num = 9
    shstrndx = 8

    elf_header = build_elf_header(sh_offset, sh_num, shstrndx)

    section_headers = build_section_headers_with_maps(
      section_data, offsets, shstr_offsets, section_name, length(maps)
    )

    elf = IO.iodata_to_binary([elf_header, section_data, section_headers])
    {:ok, elf}
  end

  # ============================================================================
  # String Tables
  # ============================================================================

  defp build_shstrtab(names) do
    {table, offsets} =
      Enum.reduce(names, {<<0>>, %{}}, fn name, {bin, offsets} ->
        offset = byte_size(bin)
        {<<bin::binary, name::binary, 0>>, Map.put(offsets, name, offset)}
      end)

    {table, offsets}
  end

  defp build_strtab(names) do
    {table, offsets} =
      Enum.reduce(names, {<<0>>, %{}}, fn name, {bin, offsets} ->
        offset = byte_size(bin)
        {<<bin::binary, name::binary, 0>>, Map.put(offsets, name, offset)}
      end)

    {table, offsets}
  end

  # ============================================================================
  # Symbol Table
  # ============================================================================

  defp build_symtab_no_maps(func_name_offset, text_size) do
    null_sym = <<0::little-32, 0::8, 0::8, 0::little-16, 0::little-64, 0::little-64>>

    st_info = @stb_global <<< 4 ||| @stt_func
    func_sym =
      <<func_name_offset::little-32, st_info::8, 0::8, 1::little-16,
        0::little-64, text_size::little-64>>

    <<null_sym::binary, func_sym::binary>>
  end

  defp build_symtab_with_maps(func_name_offset, text_size, maps, str_name_offsets, maps_section_size) do
    null_sym = <<0::little-32, 0::8, 0::8, 0::little-16, 0::little-64, 0::little-64>>

    # Function symbol: STB_GLOBAL | STT_FUNC, section index 1 (.text)
    func_info = @stb_global <<< 4 ||| @stt_func
    func_sym =
      <<func_name_offset::little-32, func_info::8, 0::8, 1::little-16,
        0::little-64, text_size::little-64>>

    # Map symbols: STB_GLOBAL | STT_OBJECT, section index 3 (.maps)
    map_struct_size = if maps == [], do: 0, else: div(maps_section_size, length(maps))
    map_syms =
      Enum.map(maps, fn md ->
        name_offset = Map.fetch!(str_name_offsets, Atom.to_string(md.name))
        st_info = @stb_global <<< 4 ||| @stt_object
        st_value = md.index * map_struct_size
        <<name_offset::little-32, st_info::8, 0::8, 3::little-16,
          st_value::little-64, map_struct_size::little-64>>
      end)

    IO.iodata_to_binary([null_sym, func_sym | map_syms])
  end

  # ============================================================================
  # Relocations
  # ============================================================================

  defp build_relocations(relocations, _num_maps) do
    # Each relocation: Elf64_Rel {r_offset: u64, r_info: u64}
    # r_info = (sym_index << 32) | R_BPF_64_64
    # sym_index: null=0, func=1, first_map=2, etc.
    entries =
      Enum.map(relocations, fn {byte_offset, map_index} ->
        sym_index = 2 + map_index  # skip null + func symbols
        r_info = (sym_index <<< 32) ||| @r_bpf_64_64
        <<byte_offset::little-64, r_info::little-64>>
      end)

    IO.iodata_to_binary(entries)
  end

  # ============================================================================
  # Layout Calculation
  # ============================================================================

  defp calculate_layout(section_data) do
    {offsets, next_offset} =
      Enum.map_reduce(section_data, @elf_header_size, fn data, offset ->
        {offset, offset + byte_size(data)}
      end)

    {offsets, next_offset}
  end

  # ============================================================================
  # ELF Header
  # ============================================================================

  defp build_elf_header(sh_offset, sh_num, shstrndx) do
    <<
      @elf_magic::binary,
      @elfclass64::8,
      @elfdata2lsb::8,
      @ev_current::8,
      @elfosabi_none::8,
      0::64,
      @et_rel::little-16,
      @em_bpf::little-16,
      1::little-32,
      0::little-64,
      0::little-64,
      sh_offset::little-64,
      0::little-32,
      @elf_header_size::little-16,
      0::little-16,
      0::little-16,
      @shdr_size::little-16,
      sh_num::little-16,
      shstrndx::little-16
    >>
  end

  # ============================================================================
  # Section Headers — No Maps (6 sections)
  # ============================================================================

  defp build_section_headers_no_maps(section_data, offsets, shstr_offsets, section_name) do
    [text_data, _license_data, _symtab, _strtab, _shstrtab] = section_data
    [text_off, license_off, symtab_off, strtab_off, shstrtab_off] = offsets

    sections = [
      # 0: Null
      encode_shdr(%{sh_name: 0, sh_type: @sht_null, sh_flags: 0, sh_offset: 0,
        sh_size: 0, sh_link: 0, sh_info: 0, sh_addralign: 0, sh_entsize: 0}),
      # 1: .text
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, section_name), sh_type: @sht_progbits,
        sh_flags: @shf_alloc ||| @shf_execinstr, sh_offset: text_off,
        sh_size: byte_size(text_data), sh_link: 0, sh_info: 0, sh_addralign: 8, sh_entsize: 0}),
      # 2: .license
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".license"), sh_type: @sht_progbits,
        sh_flags: @shf_alloc, sh_offset: license_off,
        sh_size: byte_size(Enum.at(section_data, 1)), sh_link: 0, sh_info: 0,
        sh_addralign: 1, sh_entsize: 0}),
      # 3: .symtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".symtab"), sh_type: @sht_symtab,
        sh_flags: 0, sh_offset: symtab_off,
        sh_size: byte_size(Enum.at(section_data, 2)), sh_link: 4, sh_info: 1,
        sh_addralign: 8, sh_entsize: @sym_entry_size}),
      # 4: .strtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".strtab"), sh_type: @sht_strtab,
        sh_flags: 0, sh_offset: strtab_off,
        sh_size: byte_size(Enum.at(section_data, 3)), sh_link: 0, sh_info: 0,
        sh_addralign: 1, sh_entsize: 0}),
      # 5: .shstrtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".shstrtab"), sh_type: @sht_strtab,
        sh_flags: 0, sh_offset: shstrtab_off,
        sh_size: byte_size(Enum.at(section_data, 4)), sh_link: 0, sh_info: 0,
        sh_addralign: 1, sh_entsize: 0})
    ]

    IO.iodata_to_binary(sections)
  end

  # ============================================================================
  # Section Headers — With Maps (9 sections)
  # ============================================================================

  defp build_section_headers_with_maps(section_data, offsets, shstr_offsets, section_name, _num_maps) do
    [text_data, _license, _maps, _btf, _rel, _symtab, _strtab, _shstrtab] = section_data
    [text_off, license_off, maps_off, btf_off, rel_off, symtab_off, strtab_off, shstrtab_off] = offsets

    rel_section_name = ".rel" <> section_name

    # sh_info for symtab: first global symbol index = 1 (func sym)
    # But we need to know the count: null(local) + func(global) + maps(global)
    # sh_info should be the index of first non-local symbol = 1
    symtab_sh_info = 1

    sections = [
      # 0: Null
      encode_shdr(%{sh_name: 0, sh_type: @sht_null, sh_flags: 0, sh_offset: 0,
        sh_size: 0, sh_link: 0, sh_info: 0, sh_addralign: 0, sh_entsize: 0}),
      # 1: .text
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, section_name), sh_type: @sht_progbits,
        sh_flags: @shf_alloc ||| @shf_execinstr, sh_offset: text_off,
        sh_size: byte_size(text_data), sh_link: 0, sh_info: 0, sh_addralign: 8, sh_entsize: 0}),
      # 2: .license
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".license"), sh_type: @sht_progbits,
        sh_flags: @shf_alloc, sh_offset: license_off,
        sh_size: byte_size(Enum.at(section_data, 1)), sh_link: 0, sh_info: 0,
        sh_addralign: 1, sh_entsize: 0}),
      # 3: .maps
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".maps"), sh_type: @sht_progbits,
        sh_flags: @shf_alloc, sh_offset: maps_off,
        sh_size: byte_size(Enum.at(section_data, 2)), sh_link: 0, sh_info: 0,
        sh_addralign: 4, sh_entsize: 0}),
      # 4: .BTF
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".BTF"), sh_type: @sht_progbits,
        sh_flags: 0, sh_offset: btf_off,
        sh_size: byte_size(Enum.at(section_data, 3)), sh_link: 0, sh_info: 0,
        sh_addralign: 4, sh_entsize: 0}),
      # 5: .rel.text (sh_link → symtab=6, sh_info → .text=1)
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, rel_section_name), sh_type: @sht_rel,
        sh_flags: 0, sh_offset: rel_off,
        sh_size: byte_size(Enum.at(section_data, 4)), sh_link: 6, sh_info: 1,
        sh_addralign: 8, sh_entsize: @rel_entry_size}),
      # 6: .symtab (sh_link → strtab=7)
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".symtab"), sh_type: @sht_symtab,
        sh_flags: 0, sh_offset: symtab_off,
        sh_size: byte_size(Enum.at(section_data, 5)), sh_link: 7, sh_info: symtab_sh_info,
        sh_addralign: 8, sh_entsize: @sym_entry_size}),
      # 7: .strtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".strtab"), sh_type: @sht_strtab,
        sh_flags: 0, sh_offset: strtab_off,
        sh_size: byte_size(Enum.at(section_data, 6)), sh_link: 0, sh_info: 0,
        sh_addralign: 1, sh_entsize: 0}),
      # 8: .shstrtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".shstrtab"), sh_type: @sht_strtab,
        sh_flags: 0, sh_offset: shstrtab_off,
        sh_size: byte_size(Enum.at(section_data, 7)), sh_link: 0, sh_info: 0,
        sh_addralign: 1, sh_entsize: 0})
    ]

    IO.iodata_to_binary(sections)
  end

  # ============================================================================
  # Encoding
  # ============================================================================

  defp encode_shdr(%{} = s) do
    <<
      s.sh_name::little-32,
      s.sh_type::little-32,
      s.sh_flags::little-64,
      0::little-64,
      s.sh_offset::little-64,
      s.sh_size::little-64,
      s.sh_link::little-32,
      s.sh_info::little-32,
      s.sh_addralign::little-64,
      s.sh_entsize::little-64
    >>
  end
end
