defmodule VaistoBpf.TailCallTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.MapDef
  alias VaistoBpf.Helpers

  describe "MapDef prog_array" do
    test "creates valid prog_array MapDef" do
      {:ok, md} = MapDef.new(:jumps, :prog_array, :u32, :u32, 256, 0)
      assert md.map_type == :prog_array
      assert md.key_type == :u32
      assert md.value_type == :u32
      assert md.max_entries == 256
    end

    test "prog_array bpf_map_type_id is 3" do
      {:ok, md} = MapDef.new(:jumps, :prog_array, :u32, :u32, 256, 0)
      assert MapDef.bpf_map_type_id(md) == 3
    end

    test "prog_array key and value sizes are 4 bytes" do
      {:ok, md} = MapDef.new(:jumps, :prog_array, :u32, :u32, 256, 0)
      assert MapDef.key_size(md) == 4
      assert MapDef.value_size(md) == 4
    end

    test "rejects invalid key type on prog_array" do
      assert {:error, _} = MapDef.new(:jumps, :prog_array, :bad, :u32, 256, 0)
    end
  end

  describe "tail_call helper" do
    test "tail_call has helper ID 12" do
      assert {:ok, 12} = Helpers.helper_id(:tail_call)
    end

    test "tail_call type signature" do
      {:ok, {:fn, args, ret}} = Helpers.helper_type(:tail_call)
      assert args == [:u64, :u64, :u32]
      assert ret == :u32
    end

    test "tail_call has no ptr_args" do
      assert Helpers.ptr_args(:tail_call) == []
    end

    test "tail_call is known" do
      assert Helpers.known?(:tail_call)
    end
  end

  describe "full pipeline" do
    test "tail_call with context pointer compiles" do
      source = """
      (program :xdp)
      (defmap jumps :prog_array :u32 :u32 256)
      (extern bpf:tail_call [:u64 :u64 :u32] :u32)

      (defn main [ctx :XdpMd] :u32
        (do (bpf/tail_call ctx jumps 0)
            2))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "tail_call produces valid ELF with prog_array map" do
      source = """
      (program :xdp)
      (defmap jumps :prog_array :u32 :u32 256)
      (extern bpf:tail_call [:u64 :u64 :u32] :u32)

      (defn main [ctx :XdpMd] :u32
        (do (bpf/tail_call ctx jumps 0)
            2))
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
      assert <<0x7F, "ELF", _rest::binary>> = elf
    end

    test "ELF contains .maps section for prog_array" do
      source = """
      (program :xdp)
      (defmap jumps :prog_array :u32 :u32 256)
      (extern bpf:tail_call [:u64 :u64 :u32] :u32)

      (defn main [ctx :XdpMd] :u32
        (do (bpf/tail_call ctx jumps 0)
            2))
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      # .maps section name should appear in the ELF string table
      assert String.contains?(elf, ".maps")
    end

    test "tail_call IR contains call 12" do
      source = """
      (program :xdp)
      (defmap jumps :prog_array :u32 :u32 256)
      (extern bpf:tail_call [:u64 :u64 :u32] :u32)

      (defn main [ctx :XdpMd] :u32
        (do (bpf/tail_call ctx jumps 0)
            2))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)
      # BPF_CALL opcode is 0x85 (133), helper ID 12 in imm field
      assert Enum.any?(instructions, fn
        <<133, 0, 0, 0, 12, 0, 0, 0>> -> true
        _ -> false
      end)
    end
  end

  describe "preprocessor defmap with prog_array" do
    test "extracts prog_array defmap" do
      source = "(defmap jumps :prog_array :u32 :u32 256)"
      {cleaned, [md]} = VaistoBpf.Preprocessor.extract_defmaps(source)
      assert md.name == :jumps
      assert md.map_type == :prog_array
      assert md.key_type == :u32
      assert md.value_type == :u32
      assert md.max_entries == 256
      refute String.contains?(cleaned, "defmap")
    end
  end
end
