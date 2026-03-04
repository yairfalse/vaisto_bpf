defmodule VaistoBpf.GlobalDef do
  @moduledoc """
  Definition of a BPF global variable.

  Global variables map to ELF sections:
  - `.bss` — zero-initialized (defglobal without value)
  - `.data` — initialized (defglobal with value)
  - `.rodata` — read-only (defconst)

  At load time, libbpf creates internal maps for each section and
  rewrites LD_IMM64 instructions to point at the correct map slot.
  """

  alias VaistoBpf.Layout

  defstruct [:name, :type, :value, :const?, :section, :offset, :size, :index]

  @type t :: %__MODULE__{
          name: atom(),
          type: atom(),
          value: term() | nil,
          const?: boolean(),
          section: :bss | :data | :rodata,
          offset: non_neg_integer(),
          size: non_neg_integer(),
          index: non_neg_integer()
        }

  @bpf_types ~w(u8 i8 u16 i16 u32 i32 u64 i64 bool)a

  @doc """
  Create a new global variable definition.

  Returns `{:ok, %GlobalDef{}}` or `{:error, %Vaisto.Error{}}`.
  """
  def new(name, type, value, const?, index) when is_atom(name) and is_atom(type) do
    cond do
      type not in @bpf_types ->
        {:error, Vaisto.Error.new("global '#{name}': type :#{type} is not a supported BPF type")}

      const? and value == nil ->
        {:error, Vaisto.Error.new("defconst '#{name}' requires an initial value")}

      true ->
        section = cond do
          const? -> :rodata
          value != nil -> :data
          true -> :bss
        end

        size = Layout.sizeof(type)

        {:ok,
         %__MODULE__{
           name: name,
           type: type,
           value: value,
           const?: const?,
           section: section,
           offset: 0,
           size: size,
           index: index
         }}
    end
  end

  @doc """
  Assign offsets to globals within their sections.

  Groups globals by section, assigns sequential offsets with alignment,
  and returns the updated list.
  """
  def assign_offsets(globals) do
    globals
    |> Enum.group_by(& &1.section)
    |> Enum.flat_map(fn {_section, defs} ->
      {assigned, _offset} =
        Enum.map_reduce(defs, 0, fn gdef, offset ->
          aligned = Layout.align_up(offset, Layout.alignof(gdef.type))
          {%{gdef | offset: aligned}, aligned + gdef.size}
        end)

      assigned
    end)
    |> Enum.sort_by(& &1.index)
  end

  @doc """
  Total section size for a given section type.
  """
  def section_size(globals, section) do
    globals
    |> Enum.filter(&(&1.section == section))
    |> Enum.reduce(0, fn gdef, acc ->
      aligned = Layout.align_up(acc, Layout.alignof(gdef.type))
      aligned + gdef.size
    end)
  end
end
