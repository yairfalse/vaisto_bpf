defmodule VaistoBpf.MapDef do
  @moduledoc """
  BPF map definition — parsed from `(defmap name :type :key :val max_entries)`.

  Each MapDef captures the map's name, type (hash/array), key and value types,
  maximum entries, and its zero-based index (used for relocations).
  """

  alias Vaisto.Error
  alias VaistoBpf.Layout

  defstruct [:name, :map_type, :key_type, :value_type, :max_entries, :index]

  @type t :: %__MODULE__{
          name: atom(),
          map_type: :hash | :array,
          key_type: atom(),
          value_type: atom(),
          max_entries: pos_integer(),
          index: non_neg_integer()
        }

  @map_types %{hash: 1, array: 2}

  @doc """
  Create a new MapDef with validation.

  Returns `{:ok, %MapDef{}}` or `{:error, %Error{}}`.
  """
  @spec new(atom(), atom(), atom(), atom(), pos_integer(), non_neg_integer()) ::
          {:ok, t()} | {:error, Error.t()}
  def new(name, map_type, key_type, value_type, max_entries, index \\ 0) do
    cond do
      not is_atom(name) ->
        {:error, Error.new("map name must be an atom, got: #{inspect(name)}")}

      not Map.has_key?(@map_types, map_type) ->
        {:error, Error.new("unsupported map type :#{map_type}",
          hint: "supported types: :hash, :array"
        )}

      not valid_bpf_type?(key_type) ->
        {:error, Error.new("invalid map key type :#{key_type}",
          hint: "use a fixed-width BPF type like :u32 or :u64"
        )}

      not valid_bpf_type?(value_type) ->
        {:error, Error.new("invalid map value type :#{value_type}",
          hint: "use a fixed-width BPF type like :u32 or :u64"
        )}

      not is_integer(max_entries) or max_entries <= 0 ->
        {:error, Error.new("max_entries must be a positive integer, got: #{inspect(max_entries)}")}

      true ->
        {:ok, %__MODULE__{
          name: name,
          map_type: map_type,
          key_type: key_type,
          value_type: value_type,
          max_entries: max_entries,
          index: index
        }}
    end
  end

  @doc "Return the BPF map type integer ID (BPF_MAP_TYPE_HASH=1, BPF_MAP_TYPE_ARRAY=2)."
  @spec bpf_map_type_id(t()) :: non_neg_integer()
  def bpf_map_type_id(%__MODULE__{map_type: map_type}), do: Map.fetch!(@map_types, map_type)

  @doc "Key size in bytes."
  @spec key_size(t()) :: non_neg_integer()
  def key_size(%__MODULE__{key_type: key_type}), do: Layout.sizeof(key_type)

  @doc "Value size in bytes."
  @spec value_size(t()) :: non_neg_integer()
  def value_size(%__MODULE__{value_type: value_type}), do: Layout.sizeof(value_type)

  defp valid_bpf_type?(type), do: VaistoBpf.Types.bpf_type?(type)
end
