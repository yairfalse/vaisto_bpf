defmodule VaistoBpf.Layout do
  @moduledoc """
  C struct layout calculator for BPF record types.

  Follows standard C alignment rules:
  - Each field is aligned to its own natural alignment (size in bytes)
  - Struct total size is rounded up to the maximum field alignment
  - Padding bytes are inserted between fields as needed

  This is critical for interop with the kernel — eBPF structs must match
  C layout exactly for map values, tracepoint contexts, etc.
  """

  alias VaistoBpf.Types

  @type field_layout :: %{
          name: atom(),
          type: Types.bpf_type(),
          offset: non_neg_integer(),
          size: non_neg_integer()
        }

  @type struct_layout :: %{
          fields: [field_layout()],
          total_size: non_neg_integer(),
          alignment: non_neg_integer(),
          padding: [{non_neg_integer(), non_neg_integer()}]
        }

  @doc """
  Size of a BPF type in bytes.
  """
  @spec sizeof(Types.bpf_type() | {:record, atom(), [{atom(), term()}]}) :: non_neg_integer()
  def sizeof(:u8), do: 1
  def sizeof(:i8), do: 1
  def sizeof(:bool), do: 1
  def sizeof(:u16), do: 2
  def sizeof(:i16), do: 2
  def sizeof(:u32), do: 4
  def sizeof(:i32), do: 4
  def sizeof(:u64), do: 8
  def sizeof(:i64), do: 8

  def sizeof({:record, _name, fields}) do
    layout = calculate_layout(fields)
    layout.total_size
  end

  @doc """
  Alignment requirement of a BPF type in bytes.
  """
  @spec alignof(Types.bpf_type() | {:record, atom(), [{atom(), term()}]}) :: non_neg_integer()
  def alignof(:u8), do: 1
  def alignof(:i8), do: 1
  def alignof(:bool), do: 1
  def alignof(:u16), do: 2
  def alignof(:i16), do: 2
  def alignof(:u32), do: 4
  def alignof(:i32), do: 4
  def alignof(:u64), do: 8
  def alignof(:i64), do: 8

  def alignof({:record, _name, fields}) do
    fields
    |> Enum.map(fn {_name, type} -> alignof(type) end)
    |> Enum.max(fn -> 1 end)
  end

  @doc """
  Calculate the layout of a record's fields following C struct rules.

  Takes a list of `{field_name, type}` tuples (as they appear in Vaisto's
  `{:record, name, fields}` type).

  Returns a struct_layout with field offsets, padding regions, and total size.
  """
  @spec calculate_layout([{atom(), Types.bpf_type()}]) :: struct_layout()
  def calculate_layout(fields) do
    {field_layouts, padding_regions, offset, max_align} =
      Enum.reduce(fields, {[], [], 0, 1}, fn {name, type}, {layouts, pads, offset, max_align} ->
        field_align = alignof(type)
        field_size = sizeof(type)

        # Align the current offset
        aligned_offset = align_up(offset, field_align)
        padding = aligned_offset - offset

        new_pads =
          if padding > 0,
            do: [{offset, padding} | pads],
            else: pads

        layout = %{name: name, type: type, offset: aligned_offset, size: field_size}

        {
          [layout | layouts],
          new_pads,
          aligned_offset + field_size,
          max(max_align, field_align)
        }
      end)

    # Round total size to struct alignment
    total_size = align_up(offset, max_align)
    tail_padding = total_size - offset

    final_padding =
      if tail_padding > 0,
        do: [{offset, tail_padding} | padding_regions],
        else: padding_regions

    %{
      fields: Enum.reverse(field_layouts),
      total_size: total_size,
      alignment: max_align,
      padding: Enum.reverse(final_padding)
    }
  end

  @doc """
  Round `offset` up to the next multiple of `alignment`.
  """
  @spec align_up(non_neg_integer(), pos_integer()) :: non_neg_integer()
  def align_up(offset, alignment) do
    remainder = rem(offset, alignment)
    if remainder == 0, do: offset, else: offset + (alignment - remainder)
  end
end
