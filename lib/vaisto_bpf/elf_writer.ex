defmodule VaistoBpf.ElfWriter do
  @moduledoc """
  Wraps BPF bytecode in a minimal ELF relocatable object file (.o).

  Produces the standard format expected by `bpftool prog load`, libbpf,
  and the `bpf()` syscall. The output contains:

  - `.text` (or custom) section with concatenated BPF instructions
  - `.license` section with null-terminated license string
  - `.symtab` with a FUNC symbol for the program entry point
  - `.strtab` and `.shstrtab` string tables

  ## Usage

      {:ok, elf} = ElfWriter.to_elf(instructions)
      :ok = ElfWriter.write_file(instructions, "prog.o")

  ## Options

  - `:section` — program section name (default `".text"`)
  - `:license` — license string (default `"GPL"`)
  - `:function_name` — symbol name for the entry point (default `"main"`)
  """

  import Bitwise

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

  # Section flags
  @shf_alloc 0x2
  @shf_execinstr 0x4

  # Symbol binding/type
  @stb_global 1
  @stt_func 2

  # ELF header size
  @elf_header_size 64
  # Section header entry size
  @shdr_size 64
  # Symbol table entry size (Elf64_Sym)
  @sym_entry_size 24

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Convert a list of 8-byte BPF instruction binaries to an ELF binary.

  Returns `{:ok, elf_binary}` or `{:error, %Vaisto.Error{}}`.
  """
  @spec to_elf([binary()], keyword()) :: {:ok, binary()} | {:error, Vaisto.Error.t()}
  def to_elf(instructions, opts \\ []) do
    section_name = Keyword.get(opts, :section, ".text")
    license = Keyword.get(opts, :license, "GPL")
    func_name = Keyword.get(opts, :function_name, "main")

    # Build section contents
    text_data = IO.iodata_to_binary(instructions)
    license_data = <<license::binary, 0>>

    {shstrtab, shstr_offsets} = build_shstrtab(section_name)
    {strtab, func_name_offset} = build_strtab(func_name)
    symtab = build_symtab(func_name_offset, byte_size(text_data))

    # Sections in order: null, text, license, symtab, strtab, shstrtab
    section_data = [text_data, license_data, symtab, strtab, shstrtab]

    # Calculate layout: offsets for each section's data
    {offsets, sh_offset} = calculate_layout(section_data)

    sh_num = 6
    shstrndx = 5

    # Build ELF header
    elf_header = build_elf_header(sh_offset, sh_num, shstrndx)

    # Build section headers
    section_headers =
      build_section_headers(
        section_data,
        offsets,
        shstr_offsets,
        section_name
      )

    elf = IO.iodata_to_binary([elf_header, section_data, section_headers])
    {:ok, elf}
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
  # String Tables
  # ============================================================================

  @doc false
  def build_shstrtab(section_name) do
    # Section header string table: null byte + section names
    # Index 0 is always the null byte (name offset 0 = empty string)
    names = [section_name, ".license", ".symtab", ".strtab", ".shstrtab"]

    {table, offsets} =
      Enum.reduce(names, {<<0>>, %{}}, fn name, {bin, offsets} ->
        offset = byte_size(bin)
        {<<bin::binary, name::binary, 0>>, Map.put(offsets, name, offset)}
      end)

    {table, offsets}
  end

  defp build_strtab(func_name) do
    # Symbol string table: null byte + function name
    table = <<0, func_name::binary, 0>>
    # func_name starts at offset 1 (after the leading null)
    {table, 1}
  end

  # ============================================================================
  # Symbol Table
  # ============================================================================

  defp build_symtab(func_name_offset, text_size) do
    # Null symbol (required first entry)
    null_sym = <<0::little-32, 0::8, 0::8, 0::little-16, 0::little-64, 0::little-64>>

    # Function symbol: STB_GLOBAL | STT_FUNC, section index 1 (.text)
    st_info = @stb_global <<< 4 ||| @stt_func

    func_sym =
      <<func_name_offset::little-32, st_info::8, 0::8, 1::little-16,
        0::little-64, text_size::little-64>>

    <<null_sym::binary, func_sym::binary>>
  end

  # ============================================================================
  # Layout Calculation
  # ============================================================================

  defp calculate_layout(section_data) do
    # Section data starts right after the ELF header
    {offsets, next_offset} =
      Enum.map_reduce(section_data, @elf_header_size, fn data, offset ->
        {offset, offset + byte_size(data)}
      end)

    # Section header table starts after all section data
    {offsets, next_offset}
  end

  # ============================================================================
  # ELF Header
  # ============================================================================

  defp build_elf_header(sh_offset, sh_num, shstrndx) do
    <<
      # e_ident: magic + class + data + version + OS/ABI + padding
      @elf_magic::binary,
      @elfclass64::8,
      @elfdata2lsb::8,
      @ev_current::8,
      @elfosabi_none::8,
      0::64,
      # e_type, e_machine, e_version
      @et_rel::little-16,
      @em_bpf::little-16,
      1::little-32,
      # e_entry, e_phoff (no program headers for relocatable)
      0::little-64,
      0::little-64,
      # e_shoff
      sh_offset::little-64,
      # e_flags
      0::little-32,
      # e_ehsize
      @elf_header_size::little-16,
      # e_phentsize, e_phnum (no program headers)
      0::little-16,
      0::little-16,
      # e_shentsize, e_shnum, e_shstrndx
      @shdr_size::little-16,
      sh_num::little-16,
      shstrndx::little-16
    >>
  end

  # ============================================================================
  # Section Headers
  # ============================================================================

  defp build_section_headers(section_data, offsets, shstr_offsets, section_name) do
    [text_data, _license_data, _symtab, _strtab, _shstrtab] = section_data
    [text_off, license_off, symtab_off, strtab_off, shstrtab_off] = offsets

    sections = [
      # 0: Null section
      encode_shdr(%{
        sh_name: 0,
        sh_type: @sht_null,
        sh_flags: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 0,
        sh_entsize: 0
      }),
      # 1: .text (program instructions)
      encode_shdr(%{
        sh_name: Map.fetch!(shstr_offsets, section_name),
        sh_type: @sht_progbits,
        sh_flags: @shf_alloc ||| @shf_execinstr,
        sh_offset: text_off,
        sh_size: byte_size(text_data),
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 8,
        sh_entsize: 0
      }),
      # 2: .license
      encode_shdr(%{
        sh_name: Map.fetch!(shstr_offsets, ".license"),
        sh_type: @sht_progbits,
        sh_flags: @shf_alloc,
        sh_offset: license_off,
        sh_size: byte_size(Enum.at(section_data, 1)),
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 1,
        sh_entsize: 0
      }),
      # 3: .symtab (sh_link → .strtab index, sh_info → first non-local symbol)
      encode_shdr(%{
        sh_name: Map.fetch!(shstr_offsets, ".symtab"),
        sh_type: @sht_symtab,
        sh_flags: 0,
        sh_offset: symtab_off,
        sh_size: byte_size(Enum.at(section_data, 2)),
        sh_link: 4,
        sh_info: 1,
        sh_addralign: 8,
        sh_entsize: @sym_entry_size
      }),
      # 4: .strtab
      encode_shdr(%{
        sh_name: Map.fetch!(shstr_offsets, ".strtab"),
        sh_type: @sht_strtab,
        sh_flags: 0,
        sh_offset: strtab_off,
        sh_size: byte_size(Enum.at(section_data, 3)),
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 1,
        sh_entsize: 0
      }),
      # 5: .shstrtab
      encode_shdr(%{
        sh_name: Map.fetch!(shstr_offsets, ".shstrtab"),
        sh_type: @sht_strtab,
        sh_flags: 0,
        sh_offset: shstrtab_off,
        sh_size: byte_size(Enum.at(section_data, 4)),
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 1,
        sh_entsize: 0
      })
    ]

    IO.iodata_to_binary(sections)
  end

  defp encode_shdr(%{} = s) do
    <<
      s.sh_name::little-32,
      s.sh_type::little-32,
      s.sh_flags::little-64,
      # sh_addr (always 0 for relocatable)
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
