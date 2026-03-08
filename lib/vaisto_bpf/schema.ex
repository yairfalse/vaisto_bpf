defmodule VaistoBpf.Schema do
  @moduledoc """
  Compile-time metadata that survives the ELF boundary.

  A Schema captures everything needed to interact with a loaded BPF program
  at the Elixir level: map types with codecs, global variable locations,
  record layouts, and function signatures.

  Created by `VaistoBpf.compile_source_to_schema/2`.
  """

  defstruct [
    :elf_binary,
    :prog_type,
    :attach_target,
    :section_name,
    maps: %{},
    records: %{},
    globals: %{},
    functions: []
  ]

  @type t :: %__MODULE__{
          elf_binary: binary(),
          prog_type: atom() | nil,
          attach_target: String.t() | nil,
          section_name: String.t() | nil,
          maps: %{atom() => MapSchema.t()},
          records: %{atom() => [{atom(), atom()}]},
          globals: %{atom() => GlobalSchema.t()},
          functions: [{atom(), [atom()], atom()}]
        }
end

defmodule VaistoBpf.Schema.MapSchema do
  @moduledoc """
  Schema for a single BPF map, including runtime codecs.
  """

  defstruct [:name, :map_type, :key_type, :value_type, :max_entries,
             :key_codec, :value_codec]

  @type t :: %__MODULE__{
          name: atom(),
          map_type: atom(),
          key_type: atom(),
          value_type: atom(),
          max_entries: pos_integer(),
          key_codec: VaistoBpf.Codec.codec() | nil,
          value_codec: VaistoBpf.Codec.codec() | nil
        }

  @doc "Build a MapSchema from a MapDef, resolving codecs for key/value types."
  def from_map_def(%VaistoBpf.MapDef{} = md, record_defs \\ %{}) do
    %__MODULE__{
      name: md.name,
      map_type: md.map_type,
      key_type: md.key_type,
      value_type: md.value_type,
      max_entries: md.max_entries,
      key_codec: codec_for(md.key_type, record_defs),
      value_codec: codec_for(md.value_type, record_defs)
    }
  end

  defp codec_for(:none, _), do: nil

  defp codec_for(type, record_defs) do
    if VaistoBpf.Types.bpf_type?(type) do
      VaistoBpf.Codec.for_type(type)
    else
      case Map.fetch(record_defs, type) do
        {:ok, fields} ->
          VaistoBpf.Codec.for_record(fields, record_defs)

        :error ->
          raise ArgumentError,
            "unknown record type #{inspect(type)} referenced in map schema; " <>
            "available: #{inspect(Map.keys(record_defs))}"
      end
    end
  end
end

defmodule VaistoBpf.Schema.GlobalSchema do
  @moduledoc """
  Schema for a single BPF global variable.
  """

  defstruct [:name, :type, :section, :offset, :size, :const?, :codec]

  @type t :: %__MODULE__{
          name: atom(),
          type: atom(),
          section: :bss | :data | :rodata,
          offset: non_neg_integer(),
          size: non_neg_integer(),
          const?: boolean(),
          codec: VaistoBpf.Codec.codec() | nil
        }

  @doc "Build a GlobalSchema from a GlobalDef."
  def from_global_def(%VaistoBpf.GlobalDef{} = gd) do
    %__MODULE__{
      name: gd.name,
      type: gd.type,
      section: gd.section,
      offset: gd.offset,
      size: gd.size,
      const?: gd.const?,
      codec: if(VaistoBpf.Types.bpf_type?(gd.type), do: VaistoBpf.Codec.for_type(gd.type), else: nil)
    }
  end
end
