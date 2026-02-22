defmodule VaistoBpf.BTF do
  @moduledoc """
  BPF Type Format (BTF) encoder for map definitions.

  Generates BTF binary data that describes BPF maps in the modern
  BTF-defined maps format. libbpf reads this to understand map schemas.

  ## BTF Binary Layout

      ┌─────────────────────────────┐
      │  Header (24 bytes)          │  magic=0xEB9F, version=1
      ├─────────────────────────────┤
      │  Type Section               │  type descriptors (12 bytes each + members)
      ├─────────────────────────────┤
      │  String Section             │  null-terminated strings
      └─────────────────────────────┘

  ## BTF Kinds Used

  - `BTF_KIND_INT` — primitive int types (u32, u64, etc.)
  - `BTF_KIND_ARRAY` — encodes map_type and max_entries as nelems
  - `BTF_KIND_STRUCT` — the map definition (4 members)
  - `BTF_KIND_VAR` — global variable for each map
  - `BTF_KIND_DATASEC` — the `.maps` data section
  """

  import Bitwise

  alias VaistoBpf.MapDef
  alias VaistoBpf.Layout

  # BTF header constants
  @btf_magic 0xEB9F
  @btf_version 1
  @btf_header_size 24

  # BTF kinds (shifted into bits 24-28 of btf_type.info)
  @btf_kind_int 1
  @btf_kind_ptr 2
  @btf_kind_array 3
  @btf_kind_struct 4
  @btf_kind_var 14
  @btf_kind_datasec 15

  # BTF_VAR linkage
  @btf_var_global_allocated 1

  @doc """
  Encode BTF data for a list of map definitions.

  Returns `{btf_binary, maps_section_data}` where:
  - `btf_binary` is the complete .BTF section content
  - `maps_section_data` is the zero-filled .maps section content

  Each map occupies 4 * 4 = 16 bytes in .maps (the struct size for
  BTF-defined maps: type, key_size, value_size, max_entries as u32 fields).
  """
  @spec encode_for_maps([MapDef.t()]) :: {binary(), binary()}
  def encode_for_maps(map_defs) do
    # Start with empty string table (first byte is always null)
    str_tab = <<0>>

    # Phase 1: Build all types, collecting string offsets and type IDs
    {types_bin, str_tab, _next_id, var_type_ids, map_struct_size} =
      build_types(map_defs, str_tab)

    # Phase 2: Build DATASEC type
    {datasec_bin, str_tab} = build_datasec(map_defs, var_type_ids, map_struct_size, str_tab)

    type_section = <<types_bin::binary, datasec_bin::binary>>

    # Phase 3: Build header
    header = build_header(byte_size(type_section), byte_size(str_tab))

    btf_binary = <<header::binary, type_section::binary, str_tab::binary>>

    # .maps section: zero-filled, one struct per map
    maps_data = :binary.copy(<<0>>, map_struct_size * length(map_defs))

    {btf_binary, maps_data}
  end

  # ============================================================================
  # Type Building
  # ============================================================================

  # For each map, we generate:
  #   1. BTF_KIND_INT for key type (e.g., u32)
  #   2. BTF_KIND_INT for value type (e.g., u64)
  #   3. BTF_KIND_INT for u32 (index type for arrays)
  #   4. BTF_KIND_ARRAY for "type" field (nelems = map_type_id)
  #   5. BTF_KIND_PTR → ARRAY (for struct member "type")
  #   6. BTF_KIND_ARRAY for "max_entries" field (nelems = max_entries)
  #   7. BTF_KIND_PTR → ARRAY (for struct member "max_entries")
  #   8. BTF_KIND_PTR → INT (for struct member "key")
  #   9. BTF_KIND_PTR → INT (for struct member "value")
  #  10. BTF_KIND_STRUCT for the map definition
  #  11. BTF_KIND_VAR for the map variable
  #
  # libbpf's BTF-defined map parsing requires PTR indirection on all
  # struct members (matching the C macros __uint/__type which produce
  # pointer types).
  #
  # We deduplicate the INT types across all maps.

  defp build_types(map_defs, str_tab) do
    # Collect unique int types needed (filter :none and record names)
    int_types_needed =
      map_defs
      |> Enum.flat_map(fn md -> [md.key_type, md.value_type, :u32] end)
      |> Enum.reject(fn t ->
        t == :none or (is_atom(t) and Atom.to_string(t) =~ ~r/^[A-Z]/)
      end)
      |> Enum.uniq()

    # Type IDs start at 1 (0 is void)
    next_id = 1

    # Emit BTF_KIND_INT for each unique type
    {int_bins, str_tab, int_type_map, next_id} =
      Enum.reduce(int_types_needed, {<<>>, str_tab, %{}, next_id}, fn type, {bin, stab, map, nid} ->
        {name_off, stab} = add_string(stab, Atom.to_string(type))
        size_bytes = Layout.sizeof(type)
        int_bin = encode_int_type(name_off, size_bytes)
        {<<bin::binary, int_bin::binary>>, stab, Map.put(map, type, nid), nid + 1}
      end)

    # For each map, emit ARRAY + PTR types + STRUCT + VAR.
    # Hash/array maps: 4 members (type, key, value, max_entries) = 32 bytes.
    # Ringbuf maps: 2 members (type, max_entries) = 16 bytes — no key/value.
    # We use the max struct size for DATASEC sizing.
    map_struct_size = 32

    {map_bins, str_tab, next_id, var_type_ids} =
      Enum.reduce(map_defs, {<<>>, str_tab, next_id, []}, fn md, {bin, stab, nid, var_ids} ->
        u32_type_id = Map.fetch!(int_type_map, :u32)
        has_key_value = md.map_type != :ringbuf

        # ARRAY for "type" field: element=u32, nelems=map_type_id
        type_array_id = nid
        type_array_bin = encode_array_type(u32_type_id, u32_type_id, MapDef.bpf_map_type_id(md))

        # PTR → type_array (for struct member)
        type_ptr_id = nid + 1
        type_ptr_bin = encode_ptr_type(type_array_id)

        # ARRAY for "max_entries" field: element=u32, nelems=max_entries
        max_entries_array_id = nid + 2
        max_entries_array_bin = encode_array_type(u32_type_id, u32_type_id, md.max_entries)

        # PTR → max_entries_array
        max_entries_ptr_id = nid + 3
        max_entries_ptr_bin = encode_ptr_type(max_entries_array_id)

        # Shared BTF binary for type + max_entries (always present)
        base_bin = <<type_array_bin::binary, type_ptr_bin::binary,
                     max_entries_array_bin::binary, max_entries_ptr_bin::binary>>
        next_after_base = nid + 4

        # STRUCT for the map (members point to PTR types)
        {map_name_off, stab} = add_string(stab, Atom.to_string(md.name))
        {type_str_off, stab} = add_string(stab, "type")
        {max_str_off, stab} = add_string(stab, "max_entries")

        if has_key_value do
          key_type_id = Map.get(int_type_map, md.key_type, 0)
          value_type_id = Map.get(int_type_map, md.value_type, 0)

          # PTR → key INT
          key_ptr_id = next_after_base
          key_ptr_bin = encode_ptr_type(key_type_id)

          # PTR → value INT
          value_ptr_id = next_after_base + 1
          value_ptr_bin = encode_ptr_type(value_type_id)

          {key_str_off, stab} = add_string(stab, "key")
          {value_str_off, stab} = add_string(stab, "value")

          struct_id = next_after_base + 2
          struct_bin = encode_struct_type(map_name_off, map_struct_size, [
            {type_str_off, type_ptr_id, 0},
            {key_str_off, key_ptr_id, 64},
            {value_str_off, value_ptr_id, 128},
            {max_str_off, max_entries_ptr_id, 192}
          ])

          var_id = next_after_base + 3
          var_bin = encode_var_type(map_name_off, struct_id)

          combined = <<base_bin::binary, key_ptr_bin::binary, value_ptr_bin::binary,
                       struct_bin::binary, var_bin::binary>>

          {<<bin::binary, combined::binary>>, stab, next_after_base + 4, [{md.index, var_id} | var_ids]}
        else
          # Ringbuf: only type + max_entries members (16 bytes)
          ringbuf_struct_size = 16

          struct_id = next_after_base
          struct_bin = encode_struct_type(map_name_off, ringbuf_struct_size, [
            {type_str_off, type_ptr_id, 0},
            {max_str_off, max_entries_ptr_id, 64}
          ])

          var_id = next_after_base + 1
          var_bin = encode_var_type(map_name_off, struct_id)

          combined = <<base_bin::binary, struct_bin::binary, var_bin::binary>>

          {<<bin::binary, combined::binary>>, stab, next_after_base + 2, [{md.index, var_id} | var_ids]}
        end
      end)

    {<<int_bins::binary, map_bins::binary>>, str_tab, next_id, Enum.reverse(var_type_ids), map_struct_size}
  end

  # ============================================================================
  # DATASEC
  # ============================================================================

  defp build_datasec(map_defs, var_type_ids, struct_size, str_tab) do
    {name_off, str_tab} = add_string(str_tab, ".maps")

    # Each variable in the datasec: type_id(u32), offset(u32), size(u32)
    var_entries =
      Enum.map(var_type_ids, fn {index, var_type_id} ->
        offset = index * struct_size
        <<var_type_id::little-32, offset::little-32, struct_size::little-32>>
      end)

    vlen = length(var_entries)
    info = (@btf_kind_datasec <<< 24) ||| vlen
    total_size = struct_size * length(map_defs)

    header = <<name_off::little-32, info::little-32, total_size::little-32>>
    bin = IO.iodata_to_binary([header | var_entries])

    {bin, str_tab}
  end

  # ============================================================================
  # Type Encoders
  # ============================================================================

  # BTF_KIND_INT: 12-byte header + 4-byte int info
  defp encode_int_type(name_off, size_bytes) do
    info = @btf_kind_int <<< 24  # vlen=0 for INT
    # INT encoding: bits 0-7 = nr_bits, bit 8 = signed, bits 16-23 = offset
    int_data = size_bytes * 8  # nr_bits
    <<name_off::little-32, info::little-32, size_bytes::little-32,
      int_data::little-32>>
  end

  # BTF_KIND_PTR: 12-byte header only (no extra data)
  defp encode_ptr_type(referenced_type_id) do
    info = @btf_kind_ptr <<< 24
    <<0::little-32, info::little-32, referenced_type_id::little-32>>
  end

  # BTF_KIND_ARRAY: 12-byte header + 12-byte array info
  defp encode_array_type(elem_type_id, index_type_id, nelems) do
    info = @btf_kind_array <<< 24  # vlen=0
    <<0::little-32, info::little-32, 0::little-32,
      elem_type_id::little-32, index_type_id::little-32, nelems::little-32>>
  end

  # BTF_KIND_STRUCT: 12-byte header + 12 bytes per member
  defp encode_struct_type(name_off, size, members) do
    vlen = length(members)
    info = (@btf_kind_struct <<< 24) ||| vlen
    header = <<name_off::little-32, info::little-32, size::little-32>>

    member_bins =
      Enum.map(members, fn {member_name_off, type_id, bit_offset} ->
        <<member_name_off::little-32, type_id::little-32, bit_offset::little-32>>
      end)

    IO.iodata_to_binary([header | member_bins])
  end

  # BTF_KIND_VAR: 12-byte header + 4-byte linkage
  defp encode_var_type(name_off, type_id) do
    info = @btf_kind_var <<< 24  # vlen=0
    <<name_off::little-32, info::little-32, type_id::little-32,
      @btf_var_global_allocated::little-32>>
  end

  # ============================================================================
  # Header
  # ============================================================================

  defp build_header(type_len, str_len) do
    # type_off and str_off are relative to the end of the header
    <<
      @btf_magic::little-16,
      @btf_version::8,
      0::8,
      @btf_header_size::little-32,
      0::little-32,
      type_len::little-32,
      type_len::little-32,
      str_len::little-32
    >>
  end

  # ============================================================================
  # String Table
  # ============================================================================

  defp add_string(str_tab, string) do
    offset = byte_size(str_tab)
    {offset, <<str_tab::binary, string::binary, 0>>}
  end
end
