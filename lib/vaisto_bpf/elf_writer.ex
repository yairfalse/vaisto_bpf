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
  alias VaistoBpf.BTFExt

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
    globals = Keyword.get(opts, :globals, [])
    func_sigs = Keyword.get(opts, :func_sigs, [])

    if maps == [] and globals == [] and func_sigs == [] do
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
    globals = Keyword.get(opts, :globals, [])
    relocations = Keyword.get(opts, :relocations, [])
    func_offsets = Keyword.get(opts, :func_offsets, %{})
    func_sigs = Keyword.get(opts, :func_sigs, [])
    core_relos = Keyword.get(opts, :core_relos, [])

    text_data = IO.iodata_to_binary(instructions)
    license_data = <<license::binary, 0>>

    # Generate unified BTF for maps + functions + globals
    {btf_data, maps_data, func_type_ids, btf_builder} = BTF.build_program_btf(maps, func_sigs, globals)

    # Generate BTF.ext if we have function type info
    has_btf = maps != [] or globals != [] or func_sigs != []
    btf_ext_data = build_btf_ext(section_name, func_name, func_offsets, func_type_ids, func_sigs, core_relos, btf_builder)

    # Build global section data
    global_sections = build_global_sections(globals)

    # Build dynamic section list:
    # Always: text, license
    # Conditionally: .maps, .BTF, .BTF.ext, global sections (.bss, .data, .rodata)
    # Always: .rel.text, .symtab, .strtab, .shstrtab

    # Track sections dynamically with {name, type, flags, data, align, entsize, link, info}
    sections = [{section_name, @sht_progbits, @shf_alloc ||| @shf_execinstr, text_data, 8, 0}]
    text_idx = 1  # .text is always section 1

    sections = sections ++ [{".license", @sht_progbits, @shf_alloc, license_data, 1, 0}]

    # Maps section
    {sections, maps_idx} = if maps != [] do
      idx = length(sections) + 1
      {sections ++ [{".maps", @sht_progbits, @shf_alloc, maps_data, 4, 0}], idx}
    else
      {sections, nil}
    end

    # BTF section (always emit when we have any types)
    sections = if has_btf do
      sections ++ [{".BTF", @sht_progbits, 0, btf_data, 4, 0}]
    else
      sections
    end

    # BTF.ext section (emit when we have func_info)
    sections = if btf_ext_data != <<>> do
      sections ++ [{".BTF.ext", @sht_progbits, 0, btf_ext_data, 4, 0}]
    else
      sections
    end

    # Global data sections
    {sections, global_section_indices} =
      Enum.reduce(global_sections, {sections, %{}}, fn {sec_name, sec_data}, {secs, idx_map} ->
        idx = length(secs) + 1
        {secs ++ [{sec_name, @sht_progbits, @shf_alloc, sec_data, 8, 0}],
         Map.put(idx_map, sec_name, idx)}
      end)

    # Now we know all data sections. Build symbols and relocations.
    # Symbol table layout: null + func + map symbols + global section symbols + subprogram symbols
    map_names = Enum.map(maps, fn md -> Atom.to_string(md.name) end)
    global_sec_names = Enum.map(global_sections, fn {name, _} -> name end)
    sub_names = func_offsets |> Map.keys() |> Enum.sort() |> Enum.map(&Atom.to_string/1)
    all_sym_names = [func_name | map_names] ++ global_sec_names ++ sub_names

    {strtab, str_name_offsets} = build_strtab(all_sym_names)
    func_name_offset = Map.fetch!(str_name_offsets, func_name)

    # Build symbol table
    null_sym = <<0::little-32, 0::8, 0::8, 0::little-16, 0::little-64, 0::little-64>>
    func_info = @stb_global <<< 4 ||| @stt_func
    func_sym = <<func_name_offset::little-32, func_info::8, 0::8, 1::little-16,
                  0::little-64, byte_size(text_data)::little-64>>

    # Map symbols
    map_struct_size = if maps == [], do: 0, else: div(byte_size(maps_data), length(maps))
    map_syms = Enum.map(maps, fn md ->
      name_offset = Map.fetch!(str_name_offsets, Atom.to_string(md.name))
      st_info = @stb_global <<< 4 ||| @stt_object
      st_value = md.index * map_struct_size
      <<name_offset::little-32, st_info::8, 0::8, maps_idx::little-16,
        st_value::little-64, map_struct_size::little-64>>
    end)

    # Global section symbols (STT_OBJECT for the section itself)
    global_sym_start = 2 + length(maps)  # after null + func + maps
    global_sec_syms = Enum.map(global_sections, fn {sec_name, sec_data} ->
      name_offset = Map.fetch!(str_name_offsets, sec_name)
      sec_idx = Map.fetch!(global_section_indices, sec_name)
      st_info = @stb_global <<< 4 ||| @stt_object
      <<name_offset::little-32, st_info::8, 0::8, sec_idx::little-16,
        0::little-64, byte_size(sec_data)::little-64>>
    end)

    # Subprogram symbols
    sub_syms = build_subprogram_symbols(func_offsets, str_name_offsets, byte_size(text_data))

    symtab = IO.iodata_to_binary([null_sym, func_sym | map_syms] ++ global_sec_syms ++ sub_syms)

    # Build relocations - split map and global relocs
    {map_relocs, global_relocs} =
      Enum.split_with(relocations, fn
        {_offset, {:global, _, _}} -> false
        _ -> true
      end)

    # Map relocations: sym_index = 2 + map_index (after null + func)
    map_rel_entries = Enum.map(map_relocs, fn {byte_offset, map_index} ->
      sym_index = 2 + map_index
      r_info = (sym_index <<< 32) ||| @r_bpf_64_64
      <<byte_offset::little-64, r_info::little-64>>
    end)

    # Global relocations: sym_index = global_sym_start + position in global_sections
    global_sec_order = Enum.map(global_sections, fn {name, _} -> name end)
    global_rel_entries = Enum.map(global_relocs, fn {byte_offset, {:global, section, _index}} ->
      sec_name = section_name_for_global(section)
      sec_pos = Enum.find_index(global_sec_order, &(&1 == sec_name))
      sym_index = global_sym_start + sec_pos
      r_info = (sym_index <<< 32) ||| @r_bpf_64_64
      <<byte_offset::little-64, r_info::little-64>>
    end)

    rel_data = IO.iodata_to_binary(map_rel_entries ++ global_rel_entries)

    # Now add the trailing sections: rel, symtab, strtab, shstrtab
    rel_section_name = ".rel" <> section_name
    all_section_names = Enum.map(sections, fn {name, _, _, _, _, _} -> name end)
    all_section_names = all_section_names ++ [rel_section_name, ".symtab", ".strtab", ".shstrtab"]
    {shstrtab, shstr_offsets} = build_shstrtab(all_section_names)

    # Rel section indices
    rel_idx = length(sections) + 1
    symtab_idx = rel_idx + 1
    strtab_idx = symtab_idx + 1
    shstrtab_idx = strtab_idx + 1

    # Build all section data in order
    section_data_list = Enum.map(sections, fn {_, _, _, data, _, _} -> data end)
    section_data_list = section_data_list ++ [rel_data, symtab, strtab, shstrtab]

    {offsets, sh_offset} = calculate_layout(section_data_list)

    sh_num = shstrtab_idx + 1
    elf_header = build_elf_header(sh_offset, sh_num, shstrtab_idx)

    # Build section headers
    section_headers = [
      # 0: Null
      encode_shdr(%{sh_name: 0, sh_type: @sht_null, sh_flags: 0, sh_offset: 0,
        sh_size: 0, sh_link: 0, sh_info: 0, sh_addralign: 0, sh_entsize: 0})
    ]

    # Data sections
    data_shdrs =
      sections
      |> Enum.zip(offsets)
      |> Enum.map(fn {{name, type, flags, data, align, entsize}, offset} ->
        encode_shdr(%{
          sh_name: Map.fetch!(shstr_offsets, name), sh_type: type,
          sh_flags: flags, sh_offset: offset, sh_size: byte_size(data),
          sh_link: 0, sh_info: 0, sh_addralign: align, sh_entsize: entsize
        })
      end)
    section_headers = section_headers ++ data_shdrs

    # Remaining offsets after data sections
    remaining_offsets = Enum.drop(offsets, length(sections))
    [rel_off, symtab_off, strtab_off, shstrtab_off] = remaining_offsets

    section_headers = section_headers ++ [
      # .rel.text (sh_link → symtab, sh_info → .text)
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, rel_section_name), sh_type: @sht_rel,
        sh_flags: 0, sh_offset: rel_off, sh_size: byte_size(rel_data),
        sh_link: symtab_idx, sh_info: text_idx, sh_addralign: 8, sh_entsize: @rel_entry_size}),
      # .symtab (sh_link → strtab)
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".symtab"), sh_type: @sht_symtab,
        sh_flags: 0, sh_offset: symtab_off, sh_size: byte_size(symtab),
        sh_link: strtab_idx, sh_info: 1, sh_addralign: 8, sh_entsize: @sym_entry_size}),
      # .strtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".strtab"), sh_type: @sht_strtab,
        sh_flags: 0, sh_offset: strtab_off, sh_size: byte_size(strtab),
        sh_link: 0, sh_info: 0, sh_addralign: 1, sh_entsize: 0}),
      # .shstrtab
      encode_shdr(%{sh_name: Map.fetch!(shstr_offsets, ".shstrtab"), sh_type: @sht_strtab,
        sh_flags: 0, sh_offset: shstrtab_off, sh_size: byte_size(shstrtab),
        sh_link: 0, sh_info: 0, sh_addralign: 1, sh_entsize: 0})
    ]

    elf = IO.iodata_to_binary([elf_header, section_data_list, section_headers])
    {:ok, elf}
  end

  defp build_global_sections(globals) do
    alias VaistoBpf.GlobalDef

    sections = []

    bss_size = GlobalDef.section_size(globals, :bss)
    sections = if bss_size > 0 do
      sections ++ [{".bss", :binary.copy(<<0>>, bss_size)}]
    else
      sections
    end

    data_globals = Enum.filter(globals, &(&1.section == :data))
    sections = if data_globals != [] do
      data_bin = build_global_section_data(data_globals, GlobalDef.section_size(globals, :data))
      sections ++ [{".data", data_bin}]
    else
      sections
    end

    rodata_globals = Enum.filter(globals, &(&1.section == :rodata))
    sections = if rodata_globals != [] do
      rodata_bin = build_global_section_data(rodata_globals, GlobalDef.section_size(globals, :rodata))
      sections ++ [{".rodata", rodata_bin}]
    else
      sections
    end

    sections
  end

  defp build_global_section_data(globals, total_size) do
    sorted = Enum.sort_by(globals, & &1.offset)
    {bin, _pos} = Enum.reduce(sorted, {<<>>, 0}, fn gdef, {bin, pos} ->
      # Add padding
      padding = gdef.offset - pos
      bin = if padding > 0, do: <<bin::binary, 0::size(padding * 8)>>, else: bin

      # Add value
      value_bin = encode_global_value(gdef.value, gdef.size)
      {<<bin::binary, value_bin::binary>>, gdef.offset + gdef.size}
    end)

    # Pad to total size
    remaining = total_size - byte_size(bin)
    if remaining > 0, do: <<bin::binary, 0::size(remaining * 8)>>, else: bin
  end

  defp encode_global_value(value, size) when is_integer(value) do
    <<value::little-size(size * 8)>>
  end

  defp section_name_for_global(:bss), do: ".bss"
  defp section_name_for_global(:data), do: ".data"
  defp section_name_for_global(:rodata), do: ".rodata"

  # Build BTF.ext data with func_info records and optional CO-RE relocations.
  # Uses the BTF builder's string table to resolve the section name offset.
  defp build_btf_ext(section_name, _func_name, func_offsets, func_type_ids, func_sigs, core_relos, btf_builder \\ nil) do
    entry_func_type_id =
      case func_sigs do
        [{name, _, _} | _] -> Map.get(func_type_ids, name)
        _ -> nil
      end

    func_infos = BTFExt.build_func_infos(func_offsets, func_type_ids, entry_func_type_id)

    if func_infos == [] and core_relos == [] do
      <<>>
    else
      # Look up section name offset in the BTF string table, or add it
      {section_name_off, btf_builder} =
        if btf_builder do
          case Map.fetch(btf_builder.str_cache, section_name) do
            {:ok, off} -> {off, btf_builder}
            :error ->
              off = byte_size(btf_builder.str_tab)
              btf_builder = %{btf_builder |
                str_tab: <<btf_builder.str_tab::binary, section_name::binary, 0>>,
                str_cache: Map.put(btf_builder.str_cache, section_name, off)
              }
              {off, btf_builder}
          end
        else
          {0, nil}
        end

      BTFExt.encode(section_name, func_infos, section_name_off, core_relos, btf_builder)
    end
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

  defp build_subprogram_symbols(func_offsets, str_name_offsets, text_size) do
    sorted = func_offsets |> Enum.sort_by(fn {_name, offset} -> offset end)

    sorted
    |> Enum.with_index()
    |> Enum.map(fn {{name, insn_offset}, idx} ->
      name_str = Atom.to_string(name)
      name_offset = Map.fetch!(str_name_offsets, name_str)
      st_value = insn_offset * 8  # byte offset

      # Size: distance to next function or end of text
      next_offset =
        case Enum.at(sorted, idx + 1) do
          {_, next_insn} -> next_insn * 8
          nil -> text_size
        end
      st_size = next_offset - st_value

      st_info = @stb_global <<< 4 ||| @stt_func
      <<name_offset::little-32, st_info::8, 0::8, 1::little-16,
        st_value::little-64, st_size::little-64>>
    end)
  end

  # ============================================================================
  # Relocations
  # ============================================================================

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
