defmodule VaistoBpf.BTFTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.BTF
  alias VaistoBpf.MapDef

  import Bitwise

  # ============================================================================
  # Helpers
  # ============================================================================

  defp make_map(name, map_type, key, val, max, index) do
    {:ok, md} = MapDef.new(name, map_type, key, val, max, index)
    md
  end

  defp parse_btf_header(<<
         magic::little-16,
         version::8,
         _flags::8,
         hdr_len::little-32,
         type_off::little-32,
         type_len::little-32,
         str_off::little-32,
         str_len::little-32,
         _rest::binary
       >>) do
    %{
      magic: magic,
      version: version,
      hdr_len: hdr_len,
      type_off: type_off,
      type_len: type_len,
      str_off: str_off,
      str_len: str_len
    }
  end

  defp extract_type_section(btf) do
    header = parse_btf_header(btf)
    start = header.hdr_len + header.type_off
    binary_part(btf, start, header.type_len)
  end

  defp extract_string_section(btf) do
    header = parse_btf_header(btf)
    start = header.hdr_len + header.str_off
    binary_part(btf, start, header.str_len)
  end

  # Parse a single btf_type header (12 bytes) returning {name_off, info, size_or_type}
  defp parse_type_header(<<name_off::little-32, info::little-32, size_or_type::little-32>>) do
    kind = (info >>> 24) &&& 0x1F
    vlen = info &&& 0xFFFF
    %{name_off: name_off, kind: kind, vlen: vlen, size_or_type: size_or_type}
  end


  # ============================================================================
  # Tests: Header
  # ============================================================================

  describe "BTF header" do
    test "magic is 0xEB9F" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      header = parse_btf_header(btf)

      assert header.magic == 0xEB9F
    end

    test "version is 1" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      header = parse_btf_header(btf)

      assert header.version == 1
    end

    test "header length is 24" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      header = parse_btf_header(btf)

      assert header.hdr_len == 24
    end

    test "total size matches header + types + strings" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      header = parse_btf_header(btf)

      expected = header.hdr_len + header.type_len + header.str_len
      assert byte_size(btf) == expected
    end
  end

  # ============================================================================
  # Tests: Type Section
  # ============================================================================

  describe "type section" do
    test "contains BTF_KIND_INT types for key and value" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      type_section = extract_type_section(btf)

      # First types should be INTs (kind=1)
      # u32: 16 bytes (12 header + 4 int_data)
      <<first_12::binary-size(12), _int_data::binary-size(4), rest::binary>> = type_section
      first = parse_type_header(first_12)
      assert first.kind == 1, "first type should be BTF_KIND_INT"

      # Depending on dedup order, second could also be INT
      <<second_12::binary-size(12), _int_data2::binary-size(4), _rest2::binary>> = rest
      second = parse_type_header(second_12)
      assert second.kind == 1, "second type should be BTF_KIND_INT"
    end

    test "contains BTF_KIND_STRUCT for map definition" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      type_section = extract_type_section(btf)

      # Walk through all types looking for STRUCT (kind=4)
      structs = find_types_by_kind(type_section, 4)
      assert length(structs) >= 1, "should have at least one STRUCT"

      # The struct should have 4 members (vlen=4)
      struct = hd(structs)
      assert struct.vlen == 4
    end

    test "contains BTF_KIND_VAR for map variable" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      type_section = extract_type_section(btf)

      vars = find_types_by_kind(type_section, 14)
      assert length(vars) == 1, "should have one VAR"
    end

    test "contains BTF_KIND_DATASEC" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      type_section = extract_type_section(btf)

      datasecs = find_types_by_kind(type_section, 15)
      assert length(datasecs) == 1, "should have one DATASEC"
    end

    test "DATASEC vlen equals number of maps" do
      md1 = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      md2 = make_map(:data, :array, :u32, :u32, 256, 1)
      {btf, _maps} = BTF.encode_for_maps([md1, md2])
      type_section = extract_type_section(btf)

      datasecs = find_types_by_kind(type_section, 15)
      assert hd(datasecs).vlen == 2
    end
  end

  # ============================================================================
  # Tests: String Section
  # ============================================================================

  describe "string section" do
    test "starts with null byte" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      str_section = extract_string_section(btf)

      assert binary_part(str_section, 0, 1) == <<0>>
    end

    test "contains map name" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      str_section = extract_string_section(btf)

      assert String.contains?(str_section, "counters")
    end

    test "contains type names" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      str_section = extract_string_section(btf)

      assert String.contains?(str_section, "u32")
      assert String.contains?(str_section, "u64")
    end

    test "contains member names" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      str_section = extract_string_section(btf)

      assert String.contains?(str_section, "type")
      assert String.contains?(str_section, "key")
      assert String.contains?(str_section, "value")
      assert String.contains?(str_section, "max_entries")
    end

    test "contains .maps section name" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {btf, _maps} = BTF.encode_for_maps([md])
      str_section = extract_string_section(btf)

      assert String.contains?(str_section, ".maps")
    end
  end

  # ============================================================================
  # Tests: Maps Section Data
  # ============================================================================

  describe "maps section data" do
    test "is zero-filled" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      {_btf, maps_data} = BTF.encode_for_maps([md])

      assert maps_data == :binary.copy(<<0>>, 32)
    end

    test "size scales with number of maps" do
      md1 = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      md2 = make_map(:data, :array, :u32, :u32, 256, 1)
      {_btf, maps_data} = BTF.encode_for_maps([md1, md2])

      assert byte_size(maps_data) == 64
    end
  end

  # ============================================================================
  # Tests: Multiple Maps
  # ============================================================================

  describe "multiple maps" do
    test "two maps produce two VARs and one DATASEC" do
      md1 = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      md2 = make_map(:data, :array, :u32, :u32, 256, 1)
      {btf, _maps} = BTF.encode_for_maps([md1, md2])
      type_section = extract_type_section(btf)

      vars = find_types_by_kind(type_section, 14)
      assert length(vars) == 2

      datasecs = find_types_by_kind(type_section, 15)
      assert length(datasecs) == 1
    end

    test "string section contains both map names" do
      md1 = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      md2 = make_map(:data, :array, :u32, :u32, 256, 1)
      {btf, _maps} = BTF.encode_for_maps([md1, md2])
      str_section = extract_string_section(btf)

      assert String.contains?(str_section, "counters")
      assert String.contains?(str_section, "data")
    end
  end

  # ============================================================================
  # Type Walking Helper
  # ============================================================================

  # Walk the type section and collect headers matching a given kind.
  # This handles variable-length type entries by skipping the appropriate
  # number of bytes per kind.
  defp find_types_by_kind(type_section, target_kind) do
    find_types_by_kind(type_section, target_kind, [])
  end

  defp find_types_by_kind(<<>>, _target_kind, acc), do: Enum.reverse(acc)

  defp find_types_by_kind(bin, target_kind, acc) when byte_size(bin) >= 12 do
    <<header_bytes::binary-size(12), rest::binary>> = bin
    header = parse_type_header(header_bytes)

    # Calculate extra bytes after the 12-byte header
    extra = type_extra_bytes(header.kind, header.vlen)

    if byte_size(rest) < extra do
      Enum.reverse(acc)
    else
      <<_extra_data::binary-size(extra), remaining::binary>> = rest

      new_acc = if header.kind == target_kind, do: [header | acc], else: acc
      find_types_by_kind(remaining, target_kind, new_acc)
    end
  end

  defp find_types_by_kind(_bin, _target_kind, acc), do: Enum.reverse(acc)

  # Extra bytes per BTF kind
  defp type_extra_bytes(1, _vlen), do: 4           # INT: 4-byte encoding
  defp type_extra_bytes(2, _vlen), do: 0           # PTR: no extra data
  defp type_extra_bytes(3, _vlen), do: 12          # ARRAY: 12-byte info
  defp type_extra_bytes(4, vlen), do: vlen * 12    # STRUCT: 12 bytes per member
  defp type_extra_bytes(12, _vlen), do: 0          # FUNC: no extra data
  defp type_extra_bytes(13, vlen), do: vlen * 8    # FUNC_PROTO: 8 bytes per param
  defp type_extra_bytes(14, _vlen), do: 4          # VAR: 4-byte linkage
  defp type_extra_bytes(15, vlen), do: vlen * 12   # DATASEC: 12 bytes per var
  defp type_extra_bytes(_kind, _vlen), do: 0

  # ============================================================================
  # Tests: BTF Builder
  # ============================================================================

  describe "BTF builder" do
    test "new builder produces valid empty BTF" do
      btf = BTF.new() |> BTF.encode()
      header = parse_btf_header(btf)

      assert header.magic == 0xEB9F
      assert header.version == 1
      assert header.type_len == 0
      assert header.str_len == 1  # just the null byte
    end

    test "add_int deduplicates same type" do
      b = BTF.new()
      {id1, b} = BTF.add_int(b, :u32, 4)
      {id2, b} = BTF.add_int(b, :u32, 4)

      assert id1 == id2
      # Type section should have only 1 INT (16 bytes)
      assert byte_size(b.types) == 16
    end

    test "add_int assigns different IDs to different types" do
      b = BTF.new()
      {id1, b} = BTF.add_int(b, :u32, 4)
      {id2, _b} = BTF.add_int(b, :u64, 8)

      assert id1 != id2
      assert id1 == 1
      assert id2 == 2
    end

    test "add_func creates FUNC_PROTO + FUNC pair" do
      b = BTF.new()
      {func_id, b} = BTF.add_func(b, :my_func, [:u64, :u32], :u64)

      btf = BTF.encode(b)
      type_section = extract_type_section(btf)

      # Should have INTs + FUNC_PROTO + FUNC
      func_protos = find_types_by_kind(type_section, 13)
      assert length(func_protos) == 1
      assert hd(func_protos).vlen == 2  # 2 params

      funcs = find_types_by_kind(type_section, 12)
      assert length(funcs) == 1

      # func_type_ids should map the name
      assert BTF.func_type_ids(b) == %{my_func: func_id}
    end

    test "add_func with void return uses type_id 0" do
      b = BTF.new()
      {_id, b} = BTF.add_func(b, :noop, [], :unit)

      btf = BTF.encode(b)
      type_section = extract_type_section(btf)

      func_protos = find_types_by_kind(type_section, 13)
      assert length(func_protos) == 1
      # ret_type should be 0 (void) — check size_or_type field
      assert hd(func_protos).size_or_type == 0
    end

    test "build_program_btf with maps and functions" do
      md = make_map(:counters, :hash, :u32, :u64, 1024, 0)
      functions = [{:main, [:u64], :u32}]

      {btf_binary, maps_data, func_ids, _builder} = BTF.build_program_btf([md], functions, [])

      header = parse_btf_header(btf_binary)
      assert header.magic == 0xEB9F
      assert byte_size(maps_data) == 32

      type_section = extract_type_section(btf_binary)
      # Should have both map types and function types
      datasecs = find_types_by_kind(type_section, 15)
      assert length(datasecs) >= 1

      funcs = find_types_by_kind(type_section, 12)
      assert length(funcs) == 1

      assert Map.has_key?(func_ids, :main)
    end

    test "string deduplication avoids duplicate entries" do
      b = BTF.new()
      # add_struct calls add_str for member names
      {_id1, b} = BTF.add_struct(b, "test", 8, [{"field1", 0, 0}])
      {_id2, b} = BTF.add_struct(b, "test2", 8, [{"field1", 0, 0}])

      # "field1" should appear only once in string table
      str = b.str_tab
      # Count occurrences of "field1\0"
      count = count_string_occurrences(str, "field1")
      assert count == 1
    end
  end

  defp count_string_occurrences(bin, target) do
    target_with_null = target <> <<0>>
    do_count_string(bin, target_with_null, 0)
  end

  defp do_count_string(<<>>, _target, count), do: count
  defp do_count_string(bin, target, count) when byte_size(bin) < byte_size(target), do: count
  defp do_count_string(bin, target, count) do
    target_size = byte_size(target)
    if binary_part(bin, 0, target_size) == target do
      <<_::binary-size(target_size), rest::binary>> = bin
      do_count_string(rest, target, count + 1)
    else
      <<_::8, rest::binary>> = bin
      do_count_string(rest, target, count)
    end
  end
end
