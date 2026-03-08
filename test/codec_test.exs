defmodule VaistoBpf.CodecTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Codec

  describe "primitive type round-trips" do
    for type <- [:u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64] do
      test "#{type} encodes and decodes" do
        {enc, dec} = Codec.for_type(unquote(type))
        val = 42
        assert dec.(enc.(val)) == val
      end
    end

    test "u8 boundary values" do
      {enc, dec} = Codec.for_type(:u8)
      assert dec.(enc.(0)) == 0
      assert dec.(enc.(255)) == 255
    end

    test "i8 negative values" do
      {enc, dec} = Codec.for_type(:i8)
      assert dec.(enc.(-1)) == -1
      assert dec.(enc.(-128)) == -128
      assert dec.(enc.(127)) == 127
    end

    test "i32 negative values" do
      {enc, dec} = Codec.for_type(:i32)
      assert dec.(enc.(-42)) == -42
      assert dec.(enc.(-2_147_483_648)) == -2_147_483_648
    end

    test "u64 large values" do
      {enc, dec} = Codec.for_type(:u64)
      large = 0xFFFF_FFFF_FFFF_FFFF
      assert dec.(enc.(large)) == large
    end

    test "i64 negative values" do
      {enc, dec} = Codec.for_type(:i64)
      assert dec.(enc.(-1)) == -1
    end

    test "bool true/false" do
      {enc, dec} = Codec.for_type(:bool)
      assert dec.(enc.(true)) == true
      assert dec.(enc.(false)) == false
    end

    test "bool integer encoding" do
      {enc, dec} = Codec.for_type(:bool)
      assert dec.(enc.(1)) == true
      assert dec.(enc.(0)) == false
    end
  end

  describe "primitive binary sizes" do
    test "each type produces correct byte count" do
      for {type, expected_bytes} <- [u8: 1, i8: 1, u16: 2, i16: 2,
                                      u32: 4, i32: 4, u64: 8, i64: 8, bool: 1] do
        {enc, _dec} = Codec.for_type(type)
        assert byte_size(enc.(0)) == expected_bytes, "#{type} should be #{expected_bytes} bytes"
      end
    end
  end

  describe "record round-trips" do
    test "simple aligned record" do
      {enc, dec} = Codec.for_record(a: :u32, b: :u32)
      original = %{a: 10, b: 20}
      assert dec.(enc.(original)) == original
      assert byte_size(enc.(original)) == 8
    end

    test "record with padding (u32 then u64)" do
      {enc, dec} = Codec.for_record(pid: :u32, ts: :u64)
      original = %{pid: 1234, ts: 9_876_543_210}
      binary = enc.(original)

      # u32(4) + padding(4) + u64(8) = 16
      assert byte_size(binary) == 16
      assert dec.(binary) == original
    end

    test "record with leading u8 and u64" do
      {enc, dec} = Codec.for_record(flags: :u8, pid: :u64, count: :u32)
      original = %{flags: 7, pid: 12345, count: 42}
      binary = enc.(original)

      # u8(1) + pad(7) + u64(8) + u32(4) + pad(4) = 24
      assert byte_size(binary) == 24
      assert dec.(binary) == original
    end

    test "record preserves negative signed values" do
      {enc, dec} = Codec.for_record(x: :i32, y: :i64)
      original = %{x: -42, y: -100}
      assert dec.(enc.(original)) == original
    end

    test "record with bool field" do
      {enc, dec} = Codec.for_record(active: :bool, count: :u32)
      original = %{active: true, count: 100}
      binary = enc.(original)

      # bool(1) + pad(3) + u32(4) = 8
      assert byte_size(binary) == 8
      assert dec.(binary) == original
    end

    test "single field record" do
      {enc, dec} = Codec.for_record(val: :u64)
      original = %{val: 999}
      assert dec.(enc.(original)) == original
      assert byte_size(enc.(original)) == 8
    end
  end

  describe "nested record support" do
    test "for_type/2 resolves named record types" do
      record_defs = %{
        Inner: [x: :u32, y: :u32]
      }

      {enc, dec} = Codec.for_type(:Inner, record_defs)
      original = %{x: 10, y: 20}
      assert dec.(enc.(original)) == original
    end

    test "nested record in for_record/2" do
      record_defs = %{
        Addr: [ip: :u32, port: :u16]
      }

      # A record with a nested record field
      {enc, dec} = Codec.for_record([addr: :Addr, flags: :u32], record_defs)
      original = %{addr: %{ip: 167772161, port: 8080}, flags: 1}
      binary = enc.(original)
      assert dec.(binary) == original
    end

    test "for_type/2 with primitive falls through to for_type/1" do
      {enc, dec} = Codec.for_type(:u64, %{})
      assert dec.(enc.(42)) == 42
    end

    test "for_type/2 raises on unknown record" do
      assert_raise ArgumentError, ~r/unknown record type/, fn ->
        Codec.for_type(:NonExistent, %{})
      end
    end
  end
end
