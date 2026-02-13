defmodule VaistoBpf.MapDefTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.MapDef

  describe "new/6" do
    test "creates a valid hash map definition" do
      assert {:ok, md} = MapDef.new(:counters, :hash, :u32, :u64, 1024)
      assert md.name == :counters
      assert md.map_type == :hash
      assert md.key_type == :u32
      assert md.value_type == :u64
      assert md.max_entries == 1024
      assert md.index == 0
    end

    test "creates a valid array map definition" do
      assert {:ok, md} = MapDef.new(:data, :array, :u32, :u64, 256, 1)
      assert md.map_type == :array
      assert md.index == 1
    end

    test "rejects unsupported map type" do
      assert {:error, err} = MapDef.new(:m, :ringbuf, :u32, :u64, 100)
      assert err.message =~ "unsupported map type"
    end

    test "rejects invalid key type" do
      assert {:error, err} = MapDef.new(:m, :hash, :string, :u64, 100)
      assert err.message =~ "invalid map key type"
    end

    test "rejects invalid value type" do
      assert {:error, err} = MapDef.new(:m, :hash, :u32, :float, 100)
      assert err.message =~ "invalid map value type"
    end

    test "rejects zero max_entries" do
      assert {:error, err} = MapDef.new(:m, :hash, :u32, :u64, 0)
      assert err.message =~ "max_entries must be a positive integer"
    end

    test "rejects negative max_entries" do
      assert {:error, err} = MapDef.new(:m, :hash, :u32, :u64, -1)
      assert err.message =~ "max_entries must be a positive integer"
    end
  end

  describe "bpf_map_type_id/1" do
    test "hash maps return 1" do
      {:ok, md} = MapDef.new(:m, :hash, :u32, :u64, 100)
      assert MapDef.bpf_map_type_id(md) == 1
    end

    test "array maps return 2" do
      {:ok, md} = MapDef.new(:m, :array, :u32, :u64, 100)
      assert MapDef.bpf_map_type_id(md) == 2
    end
  end

  describe "key_size/1 and value_size/1" do
    test "u32 key is 4 bytes" do
      {:ok, md} = MapDef.new(:m, :hash, :u32, :u64, 100)
      assert MapDef.key_size(md) == 4
    end

    test "u64 value is 8 bytes" do
      {:ok, md} = MapDef.new(:m, :hash, :u32, :u64, 100)
      assert MapDef.value_size(md) == 8
    end

    test "u8 key is 1 byte" do
      {:ok, md} = MapDef.new(:m, :hash, :u8, :u32, 100)
      assert MapDef.key_size(md) == 1
    end

    test "u16 value is 2 bytes" do
      {:ok, md} = MapDef.new(:m, :hash, :u32, :u16, 100)
      assert MapDef.value_size(md) == 2
    end
  end
end
