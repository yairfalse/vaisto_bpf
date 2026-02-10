defmodule VaistoBpf.LayoutTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Layout

  describe "sizeof/1" do
    test "primitive types" do
      assert Layout.sizeof(:u8) == 1
      assert Layout.sizeof(:i8) == 1
      assert Layout.sizeof(:bool) == 1
      assert Layout.sizeof(:u16) == 2
      assert Layout.sizeof(:i16) == 2
      assert Layout.sizeof(:u32) == 4
      assert Layout.sizeof(:i32) == 4
      assert Layout.sizeof(:u64) == 8
      assert Layout.sizeof(:i64) == 8
    end

    test "record type delegates to layout" do
      # {flags :u8, pid :u64, count :u32} → 24 bytes (with padding)
      assert Layout.sizeof({:record, :Event, [flags: :u8, pid: :u64, count: :u32]}) == 24
    end
  end

  describe "alignof/1" do
    test "primitive types align to their size" do
      assert Layout.alignof(:u8) == 1
      assert Layout.alignof(:u32) == 4
      assert Layout.alignof(:u64) == 8
    end

    test "record alignment is max field alignment" do
      assert Layout.alignof({:record, :Event, [flags: :u8, pid: :u64, count: :u32]}) == 8
    end
  end

  describe "calculate_layout/1" do
    test "single field, no padding" do
      layout = Layout.calculate_layout([{:x, :u64}])
      assert layout.total_size == 8
      assert layout.alignment == 8
      assert [%{name: :x, offset: 0, size: 8}] = layout.fields
      assert layout.padding == []
    end

    test "two fields, same alignment" do
      layout = Layout.calculate_layout([{:a, :u32}, {:b, :u32}])
      assert layout.total_size == 8
      assert [
               %{name: :a, offset: 0, size: 4},
               %{name: :b, offset: 4, size: 4}
             ] = layout.fields
      assert layout.padding == []
    end

    test "padding between fields - u8 then u64" do
      layout = Layout.calculate_layout([{:flags, :u8}, {:pid, :u64}])
      assert layout.total_size == 16
      assert layout.alignment == 8
      assert [
               %{name: :flags, offset: 0, size: 1},
               %{name: :pid, offset: 8, size: 8}
             ] = layout.fields
      # 7 bytes of padding between flags and pid
      assert {0 + 1, 7} in layout.padding
    end

    test "design doc example: flags:u8, pid:u64, count:u32" do
      # From the design doc:
      # offset 0:  flags (u8)   — 1 byte
      # offset 1:  [pad]        — 7 bytes
      # offset 8:  pid (u64)    — 8 bytes
      # offset 16: count (u32)  — 4 bytes
      # offset 20: [pad]        — 4 bytes
      # total: 24 bytes
      layout = Layout.calculate_layout([{:flags, :u8}, {:pid, :u64}, {:count, :u32}])

      assert layout.total_size == 24
      assert layout.alignment == 8

      assert [
               %{name: :flags, offset: 0, size: 1},
               %{name: :pid, offset: 8, size: 8},
               %{name: :count, offset: 16, size: 4}
             ] = layout.fields

      # Padding: 7 bytes after flags, 4 bytes tail padding
      assert {1, 7} in layout.padding
      assert {20, 4} in layout.padding
    end

    test "no tail padding when already aligned" do
      layout = Layout.calculate_layout([{:a, :u32}, {:b, :u32}])
      assert layout.total_size == 8
      assert layout.padding == []
    end

    test "tail padding rounds to max alignment" do
      # u64 then u32: total should be 16 (rounded to 8-byte alignment)
      layout = Layout.calculate_layout([{:big, :u64}, {:small, :u32}])
      assert layout.total_size == 16
      assert {12, 4} in layout.padding
    end

    test "all u8 fields, no alignment needed" do
      layout = Layout.calculate_layout([{:a, :u8}, {:b, :u8}, {:c, :u8}])
      assert layout.total_size == 3
      assert layout.alignment == 1
      assert layout.padding == []
    end

    test "mixed sizes requiring multiple padding insertions" do
      # u8, u32, u8, u64
      layout = Layout.calculate_layout([{:a, :u8}, {:b, :u32}, {:c, :u8}, {:d, :u64}])

      assert [
               %{name: :a, offset: 0, size: 1},
               %{name: :b, offset: 4, size: 4},
               %{name: :c, offset: 8, size: 1},
               %{name: :d, offset: 16, size: 8}
             ] = layout.fields

      assert layout.total_size == 24
      assert layout.alignment == 8
    end
  end

  describe "align_up/2" do
    test "already aligned" do
      assert Layout.align_up(0, 4) == 0
      assert Layout.align_up(8, 8) == 8
      assert Layout.align_up(16, 4) == 16
    end

    test "needs alignment" do
      assert Layout.align_up(1, 4) == 4
      assert Layout.align_up(5, 8) == 8
      assert Layout.align_up(3, 2) == 4
    end
  end
end
