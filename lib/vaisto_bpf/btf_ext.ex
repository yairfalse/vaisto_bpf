defmodule VaistoBpf.BTFExt do
  @moduledoc """
  BPF Type Format extension (.BTF.ext) encoder.

  Generates the `.BTF.ext` ELF section that maps instruction offsets to
  BTF type information and CO-RE field relocations.

  ## BTF.ext Binary Layout

      ┌─────────────────────────────┐
      │  Header (32 bytes)          │  magic, version, flags, hdr_len
      ├─────────────────────────────┤
      │  func_info section          │  per-section func_info records
      ├─────────────────────────────┤
      │  line_info section          │  (empty — not implemented)
      ├─────────────────────────────┤
      │  core_relo section          │  CO-RE field relocation records
      └─────────────────────────────┘

  ## CO-RE Relocation Record (per ELF section)

  Each record is 16 bytes:
  - `insn_off` (4 bytes) — byte offset of the instruction to patch
  - `type_id` (4 bytes) — BTF type ID of the source struct
  - `access_str_off` (4 bytes) — offset into BTF strings for accessor ("0:N")
  - `kind` (4 bytes) — relocation kind (0 = BPF_CORE_FIELD_BYTE_OFFSET)
  """


  @btf_ext_magic 0xEB9F
  @btf_ext_version 1
  @btf_ext_hdr_len 32  # 8 base + 6*4 offsets/lengths (func_info, line_info, core_relo)
  @func_info_rec_size 8
  @core_relo_rec_size 16

  # CO-RE relocation kinds
  @bpf_core_field_byte_offset 0

  @doc """
  Encode a `.BTF.ext` section with func_info and optional CO-RE relocations.

  ## Parameters

  - `section_name` — ELF section name (e.g., ".text")
  - `func_infos` — list of `{insn_byte_offset, btf_func_type_id}` tuples
  - `section_name_off` — offset of the section name in the BTF string table
  - `core_relos` — list of core_relo maps (optional, default [])
  - `btf_builder` — BTF builder for resolving struct type IDs (optional)

  Returns the complete `.BTF.ext` binary.
  """
  @spec encode(String.t(), [{non_neg_integer(), non_neg_integer()}], non_neg_integer(),
               [map()], VaistoBpf.BTF.t() | nil) :: binary()
  def encode(_section_name, func_infos, section_name_off, core_relos \\ [], btf_builder \\ nil) do

    # Build func_info section
    func_info_section = build_func_info_section(func_infos, section_name_off)
    func_info_len = byte_size(func_info_section)

    # Build core_relo section
    {core_relo_section, btf_builder} = build_core_relo_section(
      core_relos, section_name_off, btf_builder
    )
    core_relo_len = byte_size(core_relo_section)

    # Layout: header | func_info | core_relo
    func_info_off = 0
    # line_info is empty, so line_info_off = func_info_off + func_info_len (where it would start)
    line_info_off = func_info_len
    core_relo_off = func_info_len  # core_relo follows func_info (no line_info)

    header = <<
      @btf_ext_magic::little-16,
      @btf_ext_version::8,
      0::8,
      @btf_ext_hdr_len::little-32,
      func_info_off::little-32,
      func_info_len::little-32,
      line_info_off::little-32,
      0::little-32,
      core_relo_off::little-32,
      core_relo_len::little-32
    >>

    _ = btf_builder  # may be updated with new strings
    <<header::binary, func_info_section::binary, core_relo_section::binary>>
  end

  @doc """
  Build func_info entries from function offsets and BTF type IDs.
  """
  @spec build_func_infos(%{atom() => non_neg_integer()}, %{atom() => non_neg_integer()}, non_neg_integer() | nil) ::
          [{non_neg_integer(), non_neg_integer()}]
  def build_func_infos(func_offsets, func_type_ids, entry_func_type_id \\ nil) do
    entry = if entry_func_type_id, do: [{0, entry_func_type_id}], else: []

    sub_infos =
      func_offsets
      |> Enum.filter(fn {name, _offset} -> Map.has_key?(func_type_ids, name) end)
      |> Enum.map(fn {name, insn_offset} ->
        byte_offset = insn_offset * 8
        type_id = Map.fetch!(func_type_ids, name)
        {byte_offset, type_id}
      end)

    (entry ++ sub_infos)
    |> Enum.sort_by(fn {offset, _} -> offset end)
    |> Enum.uniq_by(fn {offset, _} -> offset end)
  end

  @doc """
  Build CO-RE relocation entries from assembler core_relo metadata.

  Takes the raw core_relos from the assembler and a BTF builder to resolve
  struct type IDs and encode access strings.

  Returns `{core_relo_entries, updated_btf_builder}` where entries are
  `{insn_off, type_id, access_str_off, kind}` tuples.
  """
  @spec build_core_relo_entries([map()], VaistoBpf.BTF.t() | nil) ::
          {[{non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}],
           VaistoBpf.BTF.t() | nil}
  def build_core_relo_entries([], btf), do: {[], btf}

  def build_core_relo_entries(_core_relos, nil), do: {[], nil}

  def build_core_relo_entries(core_relos, btf) do
    {entries, btf} =
      Enum.map_reduce(core_relos, btf, fn relo, btf ->
        # Look up the struct's BTF type ID from the cache
        struct_name = Atom.to_string(relo.record)

        type_id =
          case Map.fetch(btf.cache, {:struct, struct_name}) do
            {:ok, id} -> id
            :error ->
              raise ArgumentError,
                    "CO-RE relocation refers to unknown struct #{inspect(struct_name)} " <>
                      "not present in BTF cache"
          end

        # Encode access string as "0:field_index" (first deref + field)
        access_str = "0:#{relo.field_index}"
        {access_str_off, btf} = add_str_to_builder(btf, access_str)

        entry = {relo.insn_off, type_id, access_str_off, @bpf_core_field_byte_offset}
        {entry, btf}
      end)

    {entries, btf}
  end

  # ============================================================================
  # Internal Builders
  # ============================================================================

  defp build_func_info_section(func_infos, section_name_off) do
    num_info = length(func_infos)

    if num_info == 0 do
      <<>>
    else
      sec_header = <<
        section_name_off::little-32,
        num_info::little-32,
        @func_info_rec_size::little-32
      >>

      records =
        Enum.map(func_infos, fn {insn_off, type_id} ->
          <<insn_off::little-32, type_id::little-32>>
        end)

      IO.iodata_to_binary([sec_header | records])
    end
  end

  defp build_core_relo_section([], _section_name_off, btf), do: {<<>>, btf}

  defp build_core_relo_section(core_relos, section_name_off, btf) do
    {entries, btf} = build_core_relo_entries(core_relos, btf)

    if entries == [] do
      {<<>>, btf}
    else
      sec_header = <<
        section_name_off::little-32,
        length(entries)::little-32,
        @core_relo_rec_size::little-32
      >>

      records =
        Enum.map(entries, fn {insn_off, type_id, access_str_off, kind} ->
          <<insn_off::little-32, type_id::little-32, access_str_off::little-32, kind::little-32>>
        end)

      {IO.iodata_to_binary([sec_header | records]), btf}
    end
  end

  # Add a string to the BTF builder's string table
  defp add_str_to_builder(%{str_cache: cache, str_tab: tab} = btf, string) do
    case Map.fetch(cache, string) do
      {:ok, offset} ->
        {offset, btf}

      :error ->
        offset = byte_size(tab)
        btf = %{btf |
          str_tab: <<tab::binary, string::binary, 0>>,
          str_cache: Map.put(cache, string, offset)
        }
        {offset, btf}
    end
  end
end
