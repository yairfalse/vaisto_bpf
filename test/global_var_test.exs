defmodule VaistoBpf.GlobalVarTest do
  use ExUnit.Case, async: true

  alias VaistoBpf.Preprocessor
  alias VaistoBpf.GlobalDef

  describe "preprocessor extraction" do
    test "extracts defglobal without value (bss)" do
      {cleaned, globals} = Preprocessor.extract_defglobals("(defglobal counter :u64)")
      assert String.trim(cleaned) == ""
      assert length(globals) == 1
      [g] = globals
      assert g.name == :counter
      assert g.type == :u64
      assert g.value == nil
      assert g.section == :bss
    end

    test "extracts defglobal with value (data)" do
      {_cleaned, globals} = Preprocessor.extract_defglobals("(defglobal threshold :u32 100)")
      assert length(globals) == 1
      [g] = globals
      assert g.name == :threshold
      assert g.type == :u32
      assert g.value == 100
      assert g.section == :data
    end

    test "extracts defconst (rodata)" do
      {_cleaned, globals} = Preprocessor.extract_defglobals("(defconst max_size :u32 1024)")
      assert length(globals) == 1
      [g] = globals
      assert g.name == :max_size
      assert g.type == :u32
      assert g.value == 1024
      assert g.const? == true
      assert g.section == :rodata
    end

    test "extracts multiple globals with correct indices" do
      source = """
      (defglobal a :u64)
      (defglobal b :u32 42)
      (defconst c :u64 100)
      """
      {_cleaned, globals} = Preprocessor.extract_defglobals(source)
      assert length(globals) == 3
      names = Enum.map(globals, & &1.name)
      assert :a in names
      assert :b in names
      assert :c in names
    end
  end

  describe "GlobalDef" do
    test "rejects unsupported type" do
      assert {:error, _} = GlobalDef.new(:x, :string, nil, false, 0)
    end

    test "rejects defconst without value" do
      assert {:error, _} = GlobalDef.new(:x, :u64, nil, true, 0)
    end

    test "assign_offsets with alignment" do
      {:ok, g1} = GlobalDef.new(:a, :u32, nil, false, 0)
      {:ok, g2} = GlobalDef.new(:b, :u64, nil, false, 1)
      assigned = GlobalDef.assign_offsets([g1, g2])
      offsets = Map.new(assigned, fn g -> {g.name, g.offset} end)
      # u32 at 0, u64 needs 8-byte alignment so at offset 8
      assert offsets[:a] == 0
      assert offsets[:b] == 8
    end
  end

  describe "type checker" do
    test "global read type-checks" do
      source = """
      (defglobal counter :u64)
      (defn read [] :u64 counter)
      """
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "defconst read type-checks" do
      source = """
      (defconst max_val :u64 1000)
      (defn read_max [] :u64 max_val)
      """
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "set! on defglobal works" do
      source = """
      (defglobal counter :u64)
      (defn inc [] :unit (set! counter (+ counter 1)))
      """
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end

    test "set! on defconst is rejected" do
      source = """
      (defconst max_val :u64 1000)
      (defn bad [] :unit (set! max_val 42))
      """
      assert {:error, err} = VaistoBpf.compile_source(source)
      assert err.message =~ "defconst"
    end

    test "set! type mismatch is rejected" do
      source = """
      (defglobal counter :u64)
      (defn bad [x :u32] :unit (set! counter x))
      """
      assert {:error, err} = VaistoBpf.compile_source(source)
      assert err.message =~ "type mismatch"
    end
  end

  describe "emitter IR" do
    test "global read emits ld_global + ldx_mem" do
      source = """
      (defglobal counter :u64)
      (defn read [] :u64 counter)
      """
      {cleaned, _section, prog_type} = Preprocessor.extract_program(source)
      {cleaned, maps} = Preprocessor.extract_defmaps(cleaned)
      {cleaned, globals} = Preprocessor.extract_defglobals(cleaned)
      preprocessed = Preprocessor.preprocess_source(cleaned)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:ok, _type, typed_ast} = VaistoBpf.BpfTypeChecker.check(normalized, maps, prog_type, globals)
      {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
      {:ok, ir} = VaistoBpf.Emitter.emit(ast, maps, globals)

      assert Enum.any?(ir, &match?({:ld_global, _, :bss, _}, &1))
      assert Enum.any?(ir, &match?({:ldx_mem, :u64, _, _, _}, &1))
    end

    test "global write emits ld_global + stx_mem" do
      source = """
      (defglobal counter :u64)
      (defn write [val :u64] :unit (set! counter val))
      """
      {cleaned, _section, prog_type} = Preprocessor.extract_program(source)
      {cleaned, maps} = Preprocessor.extract_defmaps(cleaned)
      {cleaned, globals} = Preprocessor.extract_defglobals(cleaned)
      preprocessed = Preprocessor.preprocess_source(cleaned)
      parsed = Vaisto.Parser.parse(preprocessed)
      normalized = Preprocessor.normalize_ast(parsed)

      {:ok, _type, typed_ast} = VaistoBpf.BpfTypeChecker.check(normalized, maps, prog_type, globals)
      {:ok, ast} = VaistoBpf.Validator.validate(typed_ast)
      {:ok, ir} = VaistoBpf.Emitter.emit(ast, maps, globals)

      assert Enum.any?(ir, &match?({:ld_global, _, :bss, _}, &1))
      assert Enum.any?(ir, &match?({:stx_mem, :u64, _, _, _}, &1))
    end
  end

  describe "ELF output" do
    test "program with bss global compiles to ELF" do
      source = """
      (defglobal counter :u64)
      (defn read [] :u64 counter)
      """
      assert {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
      assert byte_size(elf) > 64
      # ELF magic
      assert <<0x7F, ?E, ?L, ?F, _rest::binary>> = elf
    end

    test "program with data global compiles to ELF" do
      source = """
      (defglobal threshold :u32 100)
      (defn get [] :u32 threshold)
      """
      assert {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
    end

    test "program with rodata constant compiles to ELF" do
      source = """
      (defconst max_entries :u64 1024)
      (defn get_max [] :u64 max_entries)
      """
      assert {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert is_binary(elf)
    end
  end
end
