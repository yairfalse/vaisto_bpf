defmodule VaistoBpf.ContextTypesTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.ContextTypes

  describe "all/0" do
    test "returns map with all three context types" do
      all = ContextTypes.all()
      assert Map.has_key?(all, :XdpMd)
      assert Map.has_key?(all, :SkBuff)
      assert Map.has_key?(all, :PtRegs)
    end
  end

  describe "fields/1" do
    test "XdpMd has 6 fields starting with data" do
      fields = ContextTypes.fields(:XdpMd)
      assert length(fields) == 6
      assert {:data, :u32} == hd(fields)
      assert {:data_end, :u32} == Enum.at(fields, 1)
      assert {:egress_ifindex, :u32} == List.last(fields)
    end

    test "SkBuff has 27 fields" do
      fields = ContextTypes.fields(:SkBuff)
      assert length(fields) == 27
      assert {:len, :u32} == hd(fields)
    end

    test "PtRegs has 21 u64 fields" do
      fields = ContextTypes.fields(:PtRegs)
      assert length(fields) == 21
      assert Enum.all?(fields, fn {_name, type} -> type == :u64 end)
    end

    test "returns nil for unknown type" do
      assert ContextTypes.fields(:Unknown) == nil
    end
  end

  describe "context_for_program/1" do
    test "xdp maps to XdpMd" do
      assert ContextTypes.context_for_program(:xdp) == :XdpMd
    end

    test "tc maps to SkBuff" do
      assert ContextTypes.context_for_program(:tc) == :SkBuff
    end

    test "socket_filter maps to SkBuff" do
      assert ContextTypes.context_for_program(:socket_filter) == :SkBuff
    end

    test "kprobe maps to PtRegs" do
      assert ContextTypes.context_for_program(:kprobe) == :PtRegs
    end

    test "tracepoint maps to nil (varies per tracepoint)" do
      assert ContextTypes.context_for_program(:tracepoint) == nil
    end

    test "unknown program type returns nil" do
      assert ContextTypes.context_for_program(:unknown) == nil
    end
  end

  describe "builtin?/1" do
    test "returns true for built-in types" do
      assert ContextTypes.builtin?(:XdpMd)
      assert ContextTypes.builtin?(:SkBuff)
      assert ContextTypes.builtin?(:PtRegs)
    end

    test "returns false for non-builtin types" do
      refute ContextTypes.builtin?(:Foo)
      refute ContextTypes.builtin?(:Event)
    end
  end

  describe "layout compatibility" do
    test "XdpMd fields have expected offsets (all u32)" do
      fields = ContextTypes.fields(:XdpMd)
      layout = VaistoBpf.Layout.calculate_layout(fields)

      offsets = Map.new(layout.fields, fn fl -> {fl.name, fl.offset} end)
      assert offsets[:data] == 0
      assert offsets[:data_end] == 4
      assert offsets[:data_meta] == 8
      assert offsets[:ingress_ifindex] == 12
      assert offsets[:rx_queue_index] == 16
      assert offsets[:egress_ifindex] == 20
    end

    test "PtRegs fields have expected offsets (all u64)" do
      fields = ContextTypes.fields(:PtRegs)
      layout = VaistoBpf.Layout.calculate_layout(fields)

      offsets = Map.new(layout.fields, fn fl -> {fl.name, fl.offset} end)
      assert offsets[:r15] == 0
      assert offsets[:r14] == 8
      assert offsets[:rax] == 80
    end
  end
end
