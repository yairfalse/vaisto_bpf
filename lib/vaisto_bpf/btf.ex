defmodule VaistoBpf.BTF do
  @moduledoc """
  BPF Type Format (BTF) encoder with stateful builder.

  Provides a composable builder API for generating BTF binary data that
  describes BPF maps, functions, global variables, and record types.

  ## Builder API

      btf = BTF.new()
            |> BTF.add_int(:u32, 4)
            |> BTF.add_int(:u64, 8)
            |> BTF.add_func(:my_func, [:u64], :u32)
            |> BTF.add_datasec(".maps", total_size, vars)

      btf_binary = BTF.encode(btf)

  ## BTF Binary Layout

      ┌─────────────────────────────┐
      │  Header (24 bytes)          │  magic=0xEB9F, version=1
      ├─────────────────────────────┤
      │  Type Section               │  type descriptors (12 bytes each + members)
      ├─────────────────────────────┤
      │  String Section             │  null-terminated strings
      └─────────────────────────────┘

  ## BTF Kinds Used

  - `BTF_KIND_INT` (1) — primitive int types (u32, u64, etc.)
  - `BTF_KIND_PTR` (2) — pointer types
  - `BTF_KIND_ARRAY` (3) — array types (encodes map_type, max_entries)
  - `BTF_KIND_STRUCT` (4) — struct/record types
  - `BTF_KIND_FUNC` (12) — function descriptors
  - `BTF_KIND_FUNC_PROTO` (13) — function signatures
  - `BTF_KIND_VAR` (14) — global variable declarations
  - `BTF_KIND_DATASEC` (15) — ELF data sections
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
  @btf_kind_func 12
  @btf_kind_func_proto 13
  @btf_kind_var 14
  @btf_kind_datasec 15

  # BTF_VAR linkage
  @btf_var_global_allocated 1

  # BTF_FUNC linkage
  @btf_func_global 2

  # BPF int types that we know about
  @bpf_int_types [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64]

  defstruct [
    # Accumulated type section binary (grows as types are added)
    types: <<>>,
    # String table binary (starts with null byte)
    str_tab: <<0>>,
    # Next type ID to assign (0 = void, starts at 1)
    next_id: 1,
    # Type deduplication cache: cache_key => type_id
    # Keys: {:int, atom()} | {:ptr, type_id} | {:struct, name}
    cache: %{},
    # Function name => BTF_KIND_FUNC type_id (for BTF.ext func_info)
    func_type_ids: %{},
    # String deduplication cache: string => offset
    str_cache: %{}
  ]

  @type t :: %__MODULE__{}

  # ============================================================================
  # Builder API
  # ============================================================================

  @doc "Create a new empty BTF builder."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc """
  Add a BTF_KIND_INT type. Returns `{type_id, builder}`.
  Deduplicates by type name — adding `:u32` twice returns the same ID.
  """
  @spec add_int(t(), atom(), non_neg_integer()) :: {non_neg_integer(), t()}
  def add_int(%__MODULE__{} = b, type_name, size_bytes) do
    cache_key = {:int, type_name}

    case Map.fetch(b.cache, cache_key) do
      {:ok, existing_id} ->
        {existing_id, b}

      :error ->
        {name_off, b} = add_str(b, Atom.to_string(type_name))
        type_id = b.next_id
        int_bin = encode_int_type(name_off, size_bytes)

        b = %{b |
          types: <<b.types::binary, int_bin::binary>>,
          next_id: type_id + 1,
          cache: Map.put(b.cache, cache_key, type_id)
        }

        {type_id, b}
    end
  end

  @doc """
  Add a BTF_KIND_INT for a known BPF type atom (:u32, :u64, etc.).
  Uses `Layout.sizeof/1` to determine size. Deduplicates.
  """
  @spec add_bpf_int(t(), atom()) :: {non_neg_integer(), t()}
  def add_bpf_int(%__MODULE__{} = b, type_name) when type_name in @bpf_int_types do
    add_int(b, type_name, Layout.sizeof(type_name))
  end

  def add_bpf_int(%__MODULE__{} = b, type_name) when type_name in [:unit, :void, :bool] do
    # void/unit/bool map to type_id 0 (void)
    {0, b}
  end

  @doc "Add a BTF_KIND_PTR type. Returns `{type_id, builder}`."
  @spec add_ptr(t(), non_neg_integer()) :: {non_neg_integer(), t()}
  def add_ptr(%__MODULE__{} = b, referenced_type_id) do
    cache_key = {:ptr, referenced_type_id}

    case Map.fetch(b.cache, cache_key) do
      {:ok, existing_id} ->
        {existing_id, b}

      :error ->
        type_id = b.next_id
        info = @btf_kind_ptr <<< 24
        bin = <<0::little-32, info::little-32, referenced_type_id::little-32>>

        b = %{b |
          types: <<b.types::binary, bin::binary>>,
          next_id: type_id + 1,
          cache: Map.put(b.cache, cache_key, type_id)
        }

        {type_id, b}
    end
  end

  @doc "Add a BTF_KIND_ARRAY type. Returns `{type_id, builder}`."
  @spec add_array(t(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          {non_neg_integer(), t()}
  def add_array(%__MODULE__{} = b, elem_type_id, index_type_id, nelems) do
    type_id = b.next_id
    info = @btf_kind_array <<< 24
    bin = <<0::little-32, info::little-32, 0::little-32,
            elem_type_id::little-32, index_type_id::little-32, nelems::little-32>>

    b = %{b | types: <<b.types::binary, bin::binary>>, next_id: type_id + 1}
    {type_id, b}
  end

  @doc """
  Add a BTF_KIND_STRUCT type. Members are `{name_string, type_id, bit_offset}` tuples.
  Returns `{type_id, builder}`.
  """
  @spec add_struct(t(), String.t(), non_neg_integer(), [{String.t(), non_neg_integer(), non_neg_integer()}]) ::
          {non_neg_integer(), t()}
  def add_struct(%__MODULE__{} = b, name, size, members) do
    {name_off, b} = add_str(b, name)

    {member_bins, b} =
      Enum.map_reduce(members, b, fn {member_name, member_type_id, bit_offset}, b ->
        {member_name_off, b} = add_str(b, member_name)
        bin = <<member_name_off::little-32, member_type_id::little-32, bit_offset::little-32>>
        {bin, b}
      end)

    type_id = b.next_id
    vlen = length(members)
    info = (@btf_kind_struct <<< 24) ||| vlen
    header = <<name_off::little-32, info::little-32, size::little-32>>
    bin = IO.iodata_to_binary([header | member_bins])

    b = %{b |
      types: <<b.types::binary, bin::binary>>,
      next_id: type_id + 1,
      cache: Map.put(b.cache, {:struct, name}, type_id)
    }

    {type_id, b}
  end

  @doc "Add a BTF_KIND_VAR type. Returns `{type_id, builder}`."
  @spec add_var(t(), String.t(), non_neg_integer()) :: {non_neg_integer(), t()}
  def add_var(%__MODULE__{} = b, name, referenced_type_id) do
    {name_off, b} = add_str(b, name)
    type_id = b.next_id
    info = @btf_kind_var <<< 24
    bin = <<name_off::little-32, info::little-32, referenced_type_id::little-32,
            @btf_var_global_allocated::little-32>>

    b = %{b | types: <<b.types::binary, bin::binary>>, next_id: type_id + 1}
    {type_id, b}
  end

  @doc """
  Add a BTF_KIND_DATASEC type. Vars are `{type_id, offset, size}` tuples.
  Returns `{type_id, builder}`.
  """
  @spec add_datasec(t(), String.t(), non_neg_integer(), [{non_neg_integer(), non_neg_integer(), non_neg_integer()}]) ::
          {non_neg_integer(), t()}
  def add_datasec(%__MODULE__{} = b, name, total_size, vars) do
    {name_off, b} = add_str(b, name)

    var_bins =
      Enum.map(vars, fn {var_type_id, offset, size} ->
        <<var_type_id::little-32, offset::little-32, size::little-32>>
      end)

    type_id = b.next_id
    vlen = length(vars)
    info = (@btf_kind_datasec <<< 24) ||| vlen
    header = <<name_off::little-32, info::little-32, total_size::little-32>>
    bin = IO.iodata_to_binary([header | var_bins])

    b = %{b | types: <<b.types::binary, bin::binary>>, next_id: type_id + 1}
    {type_id, b}
  end

  @doc """
  Add a BTF_KIND_FUNC_PROTO + BTF_KIND_FUNC pair for a function.
  `param_types` are BPF type atoms, `ret_type` is a BPF type atom.
  Returns `{func_type_id, builder}`.
  """
  @spec add_func(t(), atom(), [atom()], atom()) :: {non_neg_integer(), t()}
  def add_func(%__MODULE__{} = b, name, param_types, ret_type) do
    # Ensure all param/ret types exist as BTF_KIND_INT
    {ret_type_id, b} = add_bpf_int(b, ret_type)

    {param_type_ids, b} =
      Enum.map_reduce(param_types, b, fn type, b ->
        add_bpf_int(b, type)
      end)

    # FUNC_PROTO
    proto_id = b.next_id
    param_entries =
      Enum.map(param_type_ids, fn type_id ->
        <<0::little-32, type_id::little-32>>
      end)

    vlen = length(param_types)
    proto_info = (@btf_kind_func_proto <<< 24) ||| vlen
    proto_bin = IO.iodata_to_binary([
      <<0::little-32, proto_info::little-32, ret_type_id::little-32>> | param_entries
    ])

    # FUNC
    func_id = proto_id + 1
    {name_off, b} = add_str(b, Atom.to_string(name))
    func_info = (@btf_kind_func <<< 24) ||| @btf_func_global
    func_bin = <<name_off::little-32, func_info::little-32, proto_id::little-32>>

    b = %{b |
      types: <<b.types::binary, proto_bin::binary, func_bin::binary>>,
      next_id: func_id + 1,
      func_type_ids: Map.put(b.func_type_ids, name, func_id)
    }

    {func_id, b}
  end

  @doc "Get the func_type_ids map (function name => BTF_KIND_FUNC type_id)."
  @spec func_type_ids(t()) :: %{atom() => non_neg_integer()}
  def func_type_ids(%__MODULE__{} = b), do: b.func_type_ids

  @doc """
  Encode the builder state into a complete BTF binary.
  Returns the full `.BTF` section content (header + types + strings).
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = b) do
    type_len = byte_size(b.types)
    str_len = byte_size(b.str_tab)
    header = build_header(type_len, str_len)
    <<header::binary, b.types::binary, b.str_tab::binary>>
  end

  # ============================================================================
  # High-Level Builders (compose the low-level builder API)
  # ============================================================================

  @doc """
  Build complete BTF for a program: maps, functions, and globals.

  This is the main entry point for the ELF writer. Returns
  `{btf_binary, maps_section_data, func_type_ids}`.
  """
  @spec build_program_btf([MapDef.t()], [{atom(), [atom()], atom()}], [map()]) ::
          {binary(), binary(), %{atom() => non_neg_integer()}}
  def build_program_btf(maps, functions, globals) do
    b = new()

    # Add map types
    {b, var_type_ids, map_struct_size} = add_map_types(b, maps)

    # Add .maps DATASEC if maps present
    b = if maps != [] do
      total_size = map_struct_size * length(maps)
      vars = Enum.map(var_type_ids, fn {index, var_id} ->
        {var_id, index * map_struct_size, map_struct_size}
      end)
      {_datasec_id, b} = add_datasec(b, ".maps", total_size, vars)
      b
    else
      b
    end

    # Add global variable BTF (VAR + DATASEC per section)
    b = add_global_btf(b, globals)

    # Add function types
    b = Enum.reduce(functions, b, fn {name, params, ret}, b ->
      {_id, b} = add_func(b, name, params, ret)
      b
    end)

    # Encode
    btf_binary = encode(b)
    maps_data = if maps != [] do
      :binary.copy(<<0>>, map_struct_size * length(maps))
    else
      <<>>
    end

    {btf_binary, maps_data, b.func_type_ids}
  end

  @doc """
  Encode BTF data for a list of map definitions (legacy API).

  Returns `{btf_binary, maps_section_data}`.
  """
  @spec encode_for_maps([MapDef.t()]) :: {binary(), binary()}
  def encode_for_maps(map_defs) do
    {btf_binary, maps_data, _func_ids} = build_program_btf(map_defs, [], [])
    {btf_binary, maps_data}
  end

  @doc """
  Encode BTF for function definitions (legacy API).

  Returns `{type_section_binary, string_table, func_type_ids}`.
  """
  @spec encode_func_types([{atom(), [atom()], atom()}]) ::
          {binary(), binary(), %{atom() => non_neg_integer()}}
  def encode_func_types(functions) do
    encode_func_types(functions, <<0>>, 1)
  end

  @doc """
  Encode BTF for functions with existing string table and starting type ID (legacy API).
  """
  def encode_func_types(functions, str_tab, next_id) do
    b = %__MODULE__{str_tab: str_tab, next_id: next_id}

    b = Enum.reduce(functions, b, fn {name, params, ret}, b ->
      {_id, b} = add_func(b, name, params, ret)
      b
    end)

    {b.types, b.str_tab, b.func_type_ids}
  end

  # ============================================================================
  # Map Type Building (internal)
  # ============================================================================

  # libbpf's BTF-defined map parsing requires PTR indirection on all
  # struct members (matching the C macros __uint/__type which produce
  # pointer types).

  defp add_map_types(b, map_defs) do
    # Hash/array maps: 4 members (type, key, value, max_entries) = 32 bytes.
    # Ringbuf maps: 2 members (type, max_entries) = 16 bytes.
    # Use max struct size for DATASEC sizing.
    map_struct_size = 32

    # Pre-register all needed INT types first (matches old emit order for test compat)
    int_types_needed =
      map_defs
      |> Enum.flat_map(fn md -> [md.key_type, md.value_type, :u32] end)
      |> Enum.reject(fn t ->
        t not in @bpf_int_types
      end)
      |> Enum.uniq()

    b = Enum.reduce(int_types_needed, b, fn type, b ->
      {_id, b} = add_bpf_int(b, type)
      b
    end)

    # Ensure u32 exists (needed as array index type)
    {u32_id, b} = if map_defs != [], do: add_bpf_int(b, :u32), else: {0, b}

    {b, var_type_ids} =
      Enum.reduce(map_defs, {b, []}, fn md, {b, var_ids} ->
        has_key_value = md.map_type != :ringbuf

        # ARRAY for "type" field: element=u32, nelems=map_type_id
        {type_array_id, b} = add_array(b, u32_id, u32_id, MapDef.bpf_map_type_id(md))
        {type_ptr_id, b} = add_ptr(b, type_array_id)

        # ARRAY for "max_entries" field
        {max_entries_array_id, b} = add_array(b, u32_id, u32_id, md.max_entries)
        {max_entries_ptr_id, b} = add_ptr(b, max_entries_array_id)

        if has_key_value do
          # Key and value pointer types
          {key_type_id, b} = ensure_type_id(b, md.key_type)
          {value_type_id, b} = ensure_type_id(b, md.value_type)
          {key_ptr_id, b} = add_ptr(b, key_type_id)
          {value_ptr_id, b} = add_ptr(b, value_type_id)

          # STRUCT with 4 members
          {struct_id, b} = add_struct(b, Atom.to_string(md.name), map_struct_size, [
            {"type", type_ptr_id, 0},
            {"key", key_ptr_id, 64},
            {"value", value_ptr_id, 128},
            {"max_entries", max_entries_ptr_id, 192}
          ])

          # VAR for this map
          {var_id, b} = add_var(b, Atom.to_string(md.name), struct_id)

          {b, [{md.index, var_id} | var_ids]}
        else
          # Ringbuf: only type + max_entries
          ringbuf_struct_size = 16

          {struct_id, b} = add_struct(b, Atom.to_string(md.name), ringbuf_struct_size, [
            {"type", type_ptr_id, 0},
            {"max_entries", max_entries_ptr_id, 64}
          ])

          {var_id, b} = add_var(b, Atom.to_string(md.name), struct_id)

          {b, [{md.index, var_id} | var_ids]}
        end
      end)

    {b, Enum.reverse(var_type_ids), map_struct_size}
  end

  # Ensure a type has a BTF_KIND_INT entry; returns {type_id, builder}
  defp ensure_type_id(b, type) when type in @bpf_int_types do
    add_bpf_int(b, type)
  end

  defp ensure_type_id(b, _type), do: {0, b}

  # ============================================================================
  # Global Variable BTF (internal)
  # ============================================================================

  defp add_global_btf(b, []), do: b

  defp add_global_btf(b, globals) do
    alias VaistoBpf.GlobalDef

    # Group globals by section
    by_section = Enum.group_by(globals, & &1.section)

    Enum.reduce(by_section, b, fn {section, section_globals}, b ->
      sec_name = section_name_for(section)

      # Add VAR for each global in this section
      {b, var_entries} =
        Enum.reduce(section_globals, {b, []}, fn gdef, {b, entries} ->
          {type_id, b} = add_bpf_int(b, gdef.type)
          {var_id, b} = add_var(b, Atom.to_string(gdef.name), type_id)
          entry = {var_id, gdef.offset, gdef.size}
          {b, [entry | entries]}
        end)

      var_entries = Enum.reverse(var_entries)
      total_size = GlobalDef.section_size(globals, section)

      {_datasec_id, b} = add_datasec(b, sec_name, total_size, var_entries)
      b
    end)
  end

  defp section_name_for(:bss), do: ".bss"
  defp section_name_for(:data), do: ".data"
  defp section_name_for(:rodata), do: ".rodata"

  # ============================================================================
  # String Table
  # ============================================================================

  defp add_str(%__MODULE__{} = b, string) do
    case Map.fetch(b.str_cache, string) do
      {:ok, offset} ->
        {offset, b}

      :error ->
        offset = byte_size(b.str_tab)
        b = %{b |
          str_tab: <<b.str_tab::binary, string::binary, 0>>,
          str_cache: Map.put(b.str_cache, string, offset)
        }
        {offset, b}
    end
  end

  # ============================================================================
  # Type Encoders (binary encoding helpers)
  # ============================================================================

  defp encode_int_type(name_off, size_bytes) do
    info = @btf_kind_int <<< 24
    int_data = size_bytes * 8  # nr_bits
    <<name_off::little-32, info::little-32, size_bytes::little-32,
      int_data::little-32>>
  end

  # ============================================================================
  # Header
  # ============================================================================

  defp build_header(type_len, str_len) do
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
end
