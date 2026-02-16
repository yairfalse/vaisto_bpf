defmodule VaistoBpf.FieldAccessTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.BpfTypeChecker

  defp compile_and_check(source) do
    {cleaned, maps} = Preprocessor.extract_defmaps(source)
    preprocessed = Preprocessor.preprocess_source(cleaned)
    parsed = Vaisto.Parser.parse(preprocessed)
    normalized = Preprocessor.normalize_ast(parsed)
    BpfTypeChecker.check(normalized, maps)
  end

  describe "type checker" do
    test "field access on record-typed pointer returns field type" do
      source = """
      (deftype Event [ts :u64 pid :u32])
      (defmap events :hash :u32 :Event 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_ts [key :u64] :u64
        (match (bpf/map_lookup_elem events key)
          [(Some ptr) (. ptr :ts)]
          [(None) 0]))
      """
      assert {:ok, _, _} = compile_and_check(source)
    end

    test "field access returns correct type for each field" do
      source = """
      (deftype Pair [a :u64 b :u32])
      (defmap data :hash :u32 :Pair 100)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_b [key :u64] :u32
        (match (bpf/map_lookup_elem data key)
          [(Some ptr) (. ptr :b)]
          [(None) 0]))
      """
      assert {:ok, _, _} = compile_and_check(source)
    end

    test "nonexistent field is rejected" do
      source = """
      (deftype Event [ts :u64])
      (defmap events :hash :u32 :Event 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn bad [key :u64] :u64
        (match (bpf/map_lookup_elem events key)
          [(Some ptr) (. ptr :nonexistent)]
          [(None) 0]))
      """
      assert {:error, err} = compile_and_check(source)
      assert err.message =~ "no field"
    end

    test "field access on non-record type is rejected" do
      source = """
      (defn bad [x :u64] :u64 (. x :field))
      """
      assert {:error, err} = compile_and_check(source)
      assert err.message =~ "record or pointer-to-record"
    end
  end

  describe "emitter" do
    test "field access produces LDX_MEM with correct offset" do
      source = """
      (deftype Pair [a :u32 b :u64])
      (defmap data :hash :u32 :Pair 100)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_b [key :u64] :u64
        (match (bpf/map_lookup_elem data key)
          [(Some ptr) (. ptr :b)]
          [(None) 0]))
      """

      {cleaned, maps} = Preprocessor.extract_defmaps(source)
      preprocessed = Preprocessor.preprocess_source(cleaned)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:ok, _, typed_ast} = BpfTypeChecker.check(normalized, maps)
      {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
      {:ok, ir} = VaistoBpf.Emitter.emit(ast, maps)

      # u32 (4 bytes) aligned to 8 → b is at offset 8
      # Should have LDX_MEM with offset 8
      ldx_insns = Enum.filter(ir, &match?({:ldx_mem, _, _, _, _}, &1))
      assert Enum.any?(ldx_insns, fn {:ldx_mem, _size, _dst, _src, offset} ->
        offset == 8
      end)
    end

    test "field access on first field uses offset 0" do
      source = """
      (deftype Pair [a :u64 b :u32])
      (defmap data :hash :u32 :Pair 100)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_a [key :u64] :u64
        (match (bpf/map_lookup_elem data key)
          [(Some ptr) (. ptr :a)]
          [(None) 0]))
      """

      {cleaned, maps} = Preprocessor.extract_defmaps(source)
      preprocessed = Preprocessor.preprocess_source(cleaned)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:ok, _, typed_ast} = BpfTypeChecker.check(normalized, maps)
      {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
      {:ok, ir} = VaistoBpf.Emitter.emit(ast, maps)

      ldx_insns = Enum.filter(ir, &match?({:ldx_mem, _, _, _, _}, &1))
      assert Enum.any?(ldx_insns, fn {:ldx_mem, _size, _dst, _src, offset} ->
        offset == 0
      end)
    end
  end

  describe "source integration" do
    test "deftype + defmap + lookup + field access compiles end-to-end" do
      source = """
      (deftype Event [ts :u64 pid :u64])
      (defmap events :hash :u32 :Event 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_ts [key :u64] :u64
        (match (bpf/map_lookup_elem events key)
          [(Some ptr) (. ptr :ts)]
          [(None) 0]))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)
      assert length(instructions) > 0
    end

    test "field access with padding/alignment compiles correctly" do
      source = """
      (deftype Padded [flag :u8 value :u64])
      (defmap store :hash :u32 :Padded 100)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_value [key :u64] :u64
        (match (bpf/map_lookup_elem store key)
          [(Some ptr) (. ptr :value)]
          [(None) 0]))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert is_list(instructions)

      # u8 (1 byte) padded to 8-byte alignment → value at offset 8
      # Verify in IR
      {cleaned, maps} = Preprocessor.extract_defmaps(source)
      preprocessed = Preprocessor.preprocess_source(cleaned)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)
      {:ok, _, typed_ast} = BpfTypeChecker.check(normalized, maps)
      {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
      {:ok, ir} = VaistoBpf.Emitter.emit(ast, maps)

      ldx_insns = Enum.filter(ir, &match?({:ldx_mem, _, _, _, _}, &1))
      assert Enum.any?(ldx_insns, fn {:ldx_mem, _size, _dst, _src, offset} ->
        offset == 8
      end)
    end
  end
end
