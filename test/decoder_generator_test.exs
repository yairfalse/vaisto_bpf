defmodule VaistoBpf.DecoderGeneratorTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.DecoderGenerator
  alias VaistoBpf.Layout

  describe "generate/2 source code" do
    test "generates valid module source" do
      source = DecoderGenerator.generate(:Event, [{:pid, :u32}, {:count, :u64}])

      assert source =~ "defmodule Event.Decoder"
      assert source =~ "decode_event"
      assert source =~ "encode_event"
      assert source =~ "do not edit"
    end

    test "includes padding segments for misaligned fields" do
      source = DecoderGenerator.generate(:Event, [{:flags, :u8}, {:pid, :u64}, {:count, :u32}])

      # Should have padding between u8 and u64
      assert source =~ "_pad"
      assert source =~ "binary-size("
    end

    test "no padding for naturally aligned fields" do
      source = DecoderGenerator.generate(:Pair, [{:a, :u32}, {:b, :u32}])

      # No padding needed
      refute source =~ "_pad"
    end

    test "generated decode function compiles and works" do
      source = DecoderGenerator.generate(:Simple, [{:x, :u32}, {:y, :u32}])

      [{module, _}] = Code.compile_string(source)
      assert module == Simple.Decoder

      # Create a binary: two u32 values, native endian
      binary = <<42::native-unsigned-32, 99::native-unsigned-32>>
      result = module.decode_simple(binary)
      assert result == {:Simple, 42, 99}
    end

    test "generated encode function compiles and roundtrips" do
      source = DecoderGenerator.generate(:Point, [{:x, :u32}, {:y, :u32}])
      [{module, _}] = Code.compile_string(source)

      original = {:Point, 10, 20}
      encoded = module.encode_point(original)
      decoded = module.decode_point(encoded)
      assert decoded == original
    end

    test "roundtrip with padding (u8, u64, u32)" do
      source = DecoderGenerator.generate(:Evt, [{:flags, :u8}, {:pid, :u64}, {:count, :u32}])
      [{module, _}] = Code.compile_string(source)

      original = {:Evt, 7, 12345, 42}
      encoded = module.encode_evt(original)

      # Should be 24 bytes (design doc layout)
      assert byte_size(encoded) == 24

      decoded = module.decode_evt(encoded)
      assert decoded == original
    end

    test "handles signed types" do
      source = DecoderGenerator.generate(:Signed, [{:val, :i32}])
      [{module, _}] = Code.compile_string(source)

      original = {:Signed, -42}
      encoded = module.encode_signed(original)
      decoded = module.decode_signed(encoded)
      assert decoded == original
    end

    test "handles bool type" do
      source = DecoderGenerator.generate(:Flags, [{:active, :bool}, {:count, :u32}])
      [{module, _}] = Code.compile_string(source)

      # bool is u8, so there will be 3 bytes padding before u32
      layout = Layout.calculate_layout([{:active, :bool}, {:count, :u32}])
      assert layout.total_size == 8

      original = {:Flags, 1, 100}
      encoded = module.encode_flags(original)
      assert byte_size(encoded) == 8

      decoded = module.decode_flags(encoded)
      assert decoded == original
    end
  end

  describe "generate source structure" do
    test "decode function uses correct binary pattern size" do
      source = DecoderGenerator.generate(:Big, [{:a, :u64}, {:b, :u64}])

      # u64 = 64 bits
      assert source =~ "integer-64"
    end

    test "function names are snake_case from type name" do
      source = DecoderGenerator.generate(:MyEvent, [{:x, :u32}])

      assert source =~ "decode_my_event"
      assert source =~ "encode_my_event"
    end
  end
end
