defmodule VaistoBpf.RingbufTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.MapDef
  alias VaistoBpf.Helpers
  alias VaistoBpf.Preprocessor

  describe "MapDef ringbuf" do
    test "creates valid ringbuf MapDef with :none types" do
      {:ok, md} = MapDef.new(:events, :ringbuf, :none, :none, 4096, 0)
      assert md.map_type == :ringbuf
      assert md.key_type == :none
      assert md.value_type == :none
      assert md.max_entries == 4096
    end

    test "ringbuf key and value sizes are 0" do
      {:ok, md} = MapDef.new(:events, :ringbuf, :none, :none, 4096, 0)
      assert MapDef.key_size(md) == 0
      assert MapDef.value_size(md) == 0
    end

    test "ringbuf bpf_map_type_id is 27" do
      {:ok, md} = MapDef.new(:events, :ringbuf, :none, :none, 4096, 0)
      assert MapDef.bpf_map_type_id(md) == 27
    end
  end

  describe "helpers" do
    test "ringbuf_reserve returns {:ptr, :u8}" do
      {:ok, {:fn, _, ret_type}} = Helpers.helper_type(:ringbuf_reserve)
      assert ret_type == {:ptr, :u8}
    end

    test "ringbuf helpers have correct IDs" do
      assert {:ok, 130} = Helpers.helper_id(:ringbuf_output)
      assert {:ok, 131} = Helpers.helper_id(:ringbuf_reserve)
      assert {:ok, 132} = Helpers.helper_id(:ringbuf_submit)
      assert {:ok, 133} = Helpers.helper_id(:ringbuf_discard)
    end

    test "ringbuf_submit takes 2 args" do
      {:ok, {:fn, args, _}} = Helpers.helper_type(:ringbuf_submit)
      assert length(args) == 2
    end
  end

  describe "preprocessor defmap with ringbuf" do
    test "extracts ringbuf defmap with bare 0 types" do
      source = "(defmap events :ringbuf 0 0 4096)"
      {cleaned, [md]} = Preprocessor.extract_defmaps(source)
      assert md.name == :events
      assert md.map_type == :ringbuf
      assert md.key_type == :none
      assert md.value_type == :none
      assert md.max_entries == 4096
      refute String.contains?(cleaned, "defmap")
    end

    test "regular hash defmap still works" do
      source = "(defmap counters :hash :u32 :u64 1024)"
      {_, [md]} = Preprocessor.extract_defmaps(source)
      assert md.map_type == :hash
      assert md.key_type == :u32
      assert md.value_type == :u64
    end
  end

  describe "type checker with ringbuf" do
    test "ringbuf_reserve requires match for nullable pointer" do
      source = """
      (defmap events :ringbuf 0 0 4096)
      (extern bpf:ringbuf_reserve [:u64 :u64 :u64] :u64)
      (extern bpf:ringbuf_submit [:u64 :u64] :u64)

      (defn handler [] :u64
        (match (bpf/ringbuf_reserve events 8 0)
          [(Some ptr)
           (do (bpf/ringbuf_submit ptr 0)
               0)]
          [(None) 0]))
      """
      assert {:ok, _, _} = VaistoBpf.BpfTypeChecker.check(
        Preprocessor.normalize_ast(
          Vaisto.Parser.parse(
            Preprocessor.preprocess_source(elem(Preprocessor.extract_defmaps(source), 0))
          )
        ),
        elem(Preprocessor.extract_defmaps(source), 1)
      )
    end
  end

  describe "full pipeline" do
    test "ringbuf reserve + submit compiles" do
      source = """
      (defmap events :ringbuf 0 0 4096)
      (extern bpf:ringbuf_reserve [:u64 :u64 :u64] :u64)
      (extern bpf:ringbuf_submit [:u64 :u64] :u64)
      (extern bpf:ktime_get_ns [] :u64)

      (defn handler [] :u64
        (match (bpf/ringbuf_reserve events 8 0)
          [(Some ptr)
           (do (bpf/store_u64 ptr 0 (bpf/ktime_get_ns))
               (bpf/ringbuf_submit ptr 0)
               0)]
          [(None) 0]))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "ringbuf produces valid ELF" do
      source = """
      (defmap events :ringbuf 0 0 4096)
      (extern bpf:ringbuf_reserve [:u64 :u64 :u64] :u64)
      (extern bpf:ringbuf_submit [:u64 :u64] :u64)

      (defn handler [] :u64
        (match (bpf/ringbuf_reserve events 8 0)
          [(Some ptr)
           (do (bpf/ringbuf_submit ptr 0) 0)]
          [(None) 0]))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
      # ELF magic bytes
      assert <<0x7F, "ELF", _rest::binary>> = elf
    end
  end
end
