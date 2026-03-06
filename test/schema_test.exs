defmodule VaistoBpf.SchemaTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Schema
  alias VaistoBpf.Schema.MapSchema

  describe "compile_source_to_schema/2" do
    test "returns schema with ELF binary" do
      source = """
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, %Schema{elf_binary: elf}} = VaistoBpf.compile_source_to_schema(source)
      assert is_binary(elf)
      assert byte_size(elf) > 0
    end

    test "captures prog_type from program declaration" do
      source = """
      (program :xdp)
      (defn xdp_main [ctx :XdpMd] :u32 2)
      """

      assert {:ok, %Schema{prog_type: :xdp}} = VaistoBpf.compile_source_to_schema(source)
    end

    test "captures section name" do
      source = """
      (program :xdp)
      (defn xdp_main [ctx :XdpMd] :u32 2)
      """

      assert {:ok, %Schema{section_name: "xdp"}} = VaistoBpf.compile_source_to_schema(source)
    end

    test "captures map schemas with correct types" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_update_elem [:u64 :u64 :u64 :u64] :u64)
      (defn update [key :u64 val :u64] :u64 (bpf/map_update_elem counters key val 0))
      """

      assert {:ok, %Schema{maps: maps}} = VaistoBpf.compile_source_to_schema(source)
      assert Map.has_key?(maps, :counters)

      counter_schema = maps[:counters]
      assert counter_schema.map_type == :hash
      assert counter_schema.key_type == :u32
      assert counter_schema.value_type == :u64
      assert counter_schema.max_entries == 1024
    end

    test "map schema includes working codecs" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_update_elem [:u64 :u64 :u64 :u64] :u64)
      (defn update [key :u64 val :u64] :u64 (bpf/map_update_elem counters key val 0))
      """

      assert {:ok, %Schema{maps: maps}} = VaistoBpf.compile_source_to_schema(source)
      %MapSchema{key_codec: {enc_k, dec_k}, value_codec: {enc_v, dec_v}} = maps[:counters]

      # Key codec: u32
      assert dec_k.(enc_k.(42)) == 42
      assert byte_size(enc_k.(42)) == 4

      # Value codec: u64
      assert dec_v.(enc_v.(9999)) == 9999
      assert byte_size(enc_v.(9999)) == 8
    end

    test "ringbuf map has nil key codec" do
      source = """
      (defmap events :ringbuf 0 0 4096)
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, %Schema{maps: maps}} = VaistoBpf.compile_source_to_schema(source)
      assert maps[:events].map_type == :ringbuf
      assert maps[:events].key_codec == nil
    end

    test "captures global variables" do
      source = """
      (defglobal counter :u64)
      (defconst max_val :u32 100)
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, %Schema{globals: globals}} = VaistoBpf.compile_source_to_schema(source)
      assert Map.has_key?(globals, :counter)
      assert Map.has_key?(globals, :max_val)

      assert globals[:counter].type == :u64
      assert globals[:counter].section == :bss
      assert globals[:counter].const? == false

      assert globals[:max_val].type == :u32
      assert globals[:max_val].section == :rodata
      assert globals[:max_val].const? == true
    end

    test "global schema includes working codecs" do
      source = """
      (defglobal counter :u64)
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, %Schema{globals: globals}} = VaistoBpf.compile_source_to_schema(source)
      {enc, dec} = globals[:counter].codec
      assert dec.(enc.(42)) == 42
    end

    test "captures function signatures" do
      source = """
      (defn add [x :u64 y :u64] :u64 (+ x y))
      (defn negate [x :i64] :i64 (- 0 x))
      """

      assert {:ok, %Schema{functions: funcs}} = VaistoBpf.compile_source_to_schema(source)
      assert length(funcs) >= 2

      add_sig = Enum.find(funcs, fn {name, _, _} -> name == :add end)
      assert add_sig != nil
      {_, params, ret} = add_sig
      assert params == [:u64, :u64]
      assert ret == :u64
    end

    test "captures record definitions" do
      source = """
      (deftype Event [ts :u64 pid :u32])
      (defmap events :hash :u32 :Event 1024)
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, %Schema{records: records}} = VaistoBpf.compile_source_to_schema(source)
      assert Map.has_key?(records, :Event)
      assert records[:Event] == [ts: :u64, pid: :u32]
    end

    test "map with record value type gets record codec" do
      source = """
      (deftype Event [ts :u64 pid :u32])
      (defmap events :hash :u32 :Event 1024)
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, %Schema{maps: maps}} = VaistoBpf.compile_source_to_schema(source)
      %MapSchema{value_codec: {enc, dec}} = maps[:events]
      assert enc != nil
      assert dec != nil

      original = %{ts: 12345, pid: 42}
      assert dec.(enc.(original)) == original
    end

    test "cgroup_skb program with two functions" do
      source = """
      (program :cgroup_skb)
      (defn func_a [ctx :u64] :u64 ctx)
      (defn func_b [ctx :u64] :u64 ctx)
      """

      assert {:ok, %Schema{functions: funcs, prog_type: :cgroup_skb}} =
               VaistoBpf.compile_source_to_schema(source)

      assert length(funcs) >= 2
    end

    test "propagates compilation errors" do
      source = "(defn bad [] :u64)"

      assert {:error, _} = VaistoBpf.compile_source_to_schema(source)
    end
  end
end
