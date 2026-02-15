defmodule VaistoBpf.HelpersTest do
  use ExUnit.Case, async: true
  alias VaistoBpf.Helpers

  describe "helper_id/1" do
    test "returns correct IDs for known helpers" do
      assert {:ok, 5} = Helpers.helper_id(:ktime_get_ns)
      assert {:ok, 1} = Helpers.helper_id(:map_lookup_elem)
      assert {:ok, 14} = Helpers.helper_id(:get_current_pid_tgid)
      assert {:ok, 8} = Helpers.helper_id(:get_smp_processor_id)
    end

    test "returns error for unknown helper" do
      assert {:error, "unknown BPF helper: nonexistent"} = Helpers.helper_id(:nonexistent)
    end
  end

  describe "helper_id!/1" do
    test "returns ID directly" do
      assert 5 = Helpers.helper_id!(:ktime_get_ns)
    end

    test "raises on unknown helper" do
      assert_raise RuntimeError, ~r/unknown BPF helper/, fn ->
        Helpers.helper_id!(:nonexistent)
      end
    end
  end

  describe "helper_type/1" do
    test "returns function types for known helpers" do
      assert {:ok, {:fn, [], :u64}} = Helpers.helper_type(:ktime_get_ns)
      assert {:ok, {:fn, [:u64, :u64], :u64}} = Helpers.helper_type(:map_lookup_elem)
      assert {:ok, {:fn, [:u64, :u64, :u64, :u64], :u64}} = Helpers.helper_type(:map_update_elem)
      assert {:ok, {:fn, [], :u32}} = Helpers.helper_type(:get_smp_processor_id)
    end

    test "returns error for unknown helper" do
      assert {:error, _} = Helpers.helper_type(:nonexistent)
    end
  end

  describe "ptr_args/1" do
    test "map_lookup_elem needs key as stack pointer" do
      assert [1] = Helpers.ptr_args(:map_lookup_elem)
    end

    test "map_update_elem needs key and value as stack pointers" do
      assert [1, 2] = Helpers.ptr_args(:map_update_elem)
    end

    test "ktime_get_ns has no pointer args" do
      assert [] = Helpers.ptr_args(:ktime_get_ns)
    end

    test "unknown helper returns empty list" do
      assert [] = Helpers.ptr_args(:nonexistent)
    end
  end

  describe "known?/1" do
    test "true for known helpers" do
      assert Helpers.known?(:ktime_get_ns)
      assert Helpers.known?(:map_lookup_elem)
    end

    test "false for unknown helpers" do
      refute Helpers.known?(:nonexistent)
    end
  end
end
