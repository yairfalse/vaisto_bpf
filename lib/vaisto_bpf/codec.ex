defmodule VaistoBpf.Codec do
  @moduledoc """
  Runtime encode/decode closures for BPF types.

  Converts between Elixir terms and C-layout binaries matching kernel expectations.
  Replaces the string-based `DecoderGenerator` with callable functions.

      {encode, decode} = Codec.for_type(:u32)
      encode.(42)          #=> <<42, 0, 0, 0>>  (little-endian)
      decode.(<<42, 0, 0, 0>>)  #=> 42

      {encode, decode} = Codec.for_record([pid: :u32, ts: :u64])
      encode.(%{pid: 1, ts: 100})  #=> 16-byte binary with C-aligned padding
      decode.(binary)              #=> %{pid: 1, ts: 100}
  """

  alias VaistoBpf.Layout
  alias VaistoBpf.Types

  @type codec :: {encode_fn :: (term() -> binary()), decode_fn :: (binary() -> term())}

  @doc """
  Return an `{encode, decode}` closure pair for a BPF primitive type.
  """
  @spec for_type(Types.bpf_type()) :: codec()
  def for_type(:u8), do: {&encode_u8/1, &decode_u8/1}
  def for_type(:i8), do: {&encode_i8/1, &decode_i8/1}
  def for_type(:u16), do: {&encode_u16/1, &decode_u16/1}
  def for_type(:i16), do: {&encode_i16/1, &decode_i16/1}
  def for_type(:u32), do: {&encode_u32/1, &decode_u32/1}
  def for_type(:i32), do: {&encode_i32/1, &decode_i32/1}
  def for_type(:u64), do: {&encode_u64/1, &decode_u64/1}
  def for_type(:i64), do: {&encode_i64/1, &decode_i64/1}
  def for_type(:bool), do: {&encode_bool/1, &decode_bool/1}

  @doc """
  Return an `{encode, decode}` closure pair, resolving named record types via `record_defs`.
  """
  @spec for_type(atom(), %{atom() => [{atom(), atom()}]}) :: codec()
  def for_type(type, record_defs)

  def for_type(type, _record_defs)
      when type in [:u8, :i8, :u16, :i16, :u32, :i32, :u64, :i64, :bool] do
    for_type(type)
  end

  def for_type(record_name, record_defs) when is_atom(record_name) do
    case Map.fetch(record_defs, record_name) do
      {:ok, fields} -> for_record(fields, record_defs)
      :error -> raise ArgumentError, "unknown record type #{record_name} in codec"
    end
  end

  @doc """
  Return an `{encode, decode}` closure pair for a record (struct) type.

  Fields is a keyword list of `[{field_name, bpf_type}]`.
  Uses `Layout.calculate_layout/1` for C-compatible alignment and padding.

  Encode accepts a map, decode returns a map.
  """
  @spec for_record([{atom(), Types.bpf_type()}], %{atom() => [{atom(), atom()}]}) :: codec()
  def for_record(fields, record_defs \\ %{}) do
    # Expand record-typed fields so Layout can compute alignment/size
    layout_fields = expand_fields_for_layout(fields, record_defs)
    layout = Layout.calculate_layout(layout_fields)
    field_codecs = Enum.map(fields, fn {name, type} ->
      codec = if map_size(record_defs) > 0, do: for_type(type, record_defs), else: for_type(type)
      {name, codec}
    end)

    encode_fn = fn map ->
      encode_record(map, field_codecs, layout)
    end

    decode_fn = fn binary ->
      decode_record(binary, field_codecs, layout)
    end

    {encode_fn, decode_fn}
  end

  defp expand_fields_for_layout(fields, record_defs) when map_size(record_defs) == 0, do: fields

  defp expand_fields_for_layout(fields, record_defs) do
    Enum.map(fields, fn {name, type} ->
      {name, expand_type_for_layout(type, record_defs)}
    end)
  end

  defp expand_type_for_layout(type, _record_defs)
       when type in [:u8, :i8, :u16, :i16, :u32, :i32, :u64, :i64, :bool] do
    type
  end

  defp expand_type_for_layout(record_name, record_defs) when is_atom(record_name) do
    case Map.fetch(record_defs, record_name) do
      {:ok, inner_fields} ->
        expanded = expand_fields_for_layout(inner_fields, record_defs)
        {:record, record_name, expanded}
      :error ->
        record_name
    end
  end

  # -- Primitive encoders --

  defp encode_u8(val), do: <<val::unsigned-little-8>>
  defp encode_i8(val), do: <<val::signed-little-8>>
  defp encode_u16(val), do: <<val::unsigned-little-16>>
  defp encode_i16(val), do: <<val::signed-little-16>>
  defp encode_u32(val), do: <<val::unsigned-little-32>>
  defp encode_i32(val), do: <<val::signed-little-32>>
  defp encode_u64(val), do: <<val::unsigned-little-64>>
  defp encode_i64(val), do: <<val::signed-little-64>>
  defp encode_bool(true), do: <<1::unsigned-little-8>>
  defp encode_bool(false), do: <<0::unsigned-little-8>>
  defp encode_bool(1), do: <<1::unsigned-little-8>>
  defp encode_bool(0), do: <<0::unsigned-little-8>>

  # -- Primitive decoders --

  defp decode_u8(<<val::unsigned-little-8>>), do: val
  defp decode_i8(<<val::signed-little-8>>), do: val
  defp decode_u16(<<val::unsigned-little-16>>), do: val
  defp decode_i16(<<val::signed-little-16>>), do: val
  defp decode_u32(<<val::unsigned-little-32>>), do: val
  defp decode_i32(<<val::signed-little-32>>), do: val
  defp decode_u64(<<val::unsigned-little-64>>), do: val
  defp decode_i64(<<val::signed-little-64>>), do: val
  defp decode_bool(<<0::unsigned-little-8>>), do: false
  defp decode_bool(<<_::unsigned-little-8>>), do: true

  # -- Record encode/decode --

  defp encode_record(map, field_codecs, layout) do
    buf = :binary.copy(<<0>>, layout.total_size)

    Enum.zip(field_codecs, layout.fields)
    |> Enum.reduce(buf, fn {{name, {enc, _dec}}, %{offset: offset, size: size}}, buf ->
      val = Map.fetch!(map, name)
      encoded = enc.(val)

      <<prefix::binary-size(offset), _::binary-size(size), suffix::binary>> = buf
      <<prefix::binary, encoded::binary, suffix::binary>>
    end)
  end

  defp decode_record(binary, field_codecs, layout) do
    Enum.zip(field_codecs, layout.fields)
    |> Enum.reduce(%{}, fn {{name, {_enc, dec}}, %{offset: offset, size: size}}, acc ->
      <<_::binary-size(offset), field_bytes::binary-size(size), _::binary>> = binary
      Map.put(acc, name, dec.(field_bytes))
    end)
  end
end
