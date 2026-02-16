defmodule VaistoBpf.NullablePtrTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias VaistoBpf.Types

  # Decode helper: binary instruction → struct
  defp decode(bin), do: Types.decode(bin)

  # Compile helper: source string → instruction structs
  defp compile!(source) do
    {:ok, instructions} = VaistoBpf.compile_source(source)
    Enum.map(instructions, &decode/1)
  end

  # Parse through preprocessor for type-checker-only tests
  defp parse_bpf(source) do
    source
    |> VaistoBpf.Preprocessor.preprocess_source()
    |> Vaisto.Parser.parse()
    |> VaistoBpf.Preprocessor.normalize_ast()
  end

  @jeq_imm_opcode Types.jmp_jeq() ||| Types.src_imm() ||| Types.class_jmp()
  @jne_imm_opcode Types.jmp_jne() ||| Types.src_imm() ||| Types.class_jmp()
  @call_opcode Types.jmp_call() ||| Types.class_jmp()

  # ============================================================================
  # Type Checking
  # ============================================================================

  describe "type checking" do
    test "map_lookup_elem returns {:ptr, :u64}" do
      ast = parse_bpf("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(Some v) (bpf/load_u64 v 0)]
          [(None) 0]))
      """)
      assert {:ok, _, _} = VaistoBpf.BpfTypeChecker.check(ast)
    end

    test "direct use of ptr without match is type error" do
      ast = parse_bpf("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (bpf/map_lookup_elem fd key))
      """)
      assert {:error, err} = VaistoBpf.BpfTypeChecker.check(ast)
      assert err.message =~ "return type mismatch" or err.message =~ "type"
    end

    test "match with Some/None type-checks" do
      ast = parse_bpf("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(Some ptr) (bpf/load_u64 ptr 0)]
          [(None) 0]))
      """)
      assert {:ok, _, _} = VaistoBpf.BpfTypeChecker.check(ast)
    end

    test "non-exhaustive match (Some only) is rejected" do
      ast = parse_bpf("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(Some v) (bpf/load_u64 v 0)]))
      """)
      assert {:error, err} = VaistoBpf.BpfTypeChecker.check(ast)
      assert err.message =~ "non-exhaustive"
    end

    test "non-exhaustive match (None only) is rejected" do
      ast = parse_bpf("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(None) 0]))
      """)
      assert {:error, err} = VaistoBpf.BpfTypeChecker.check(ast)
      assert err.message =~ "non-exhaustive"
    end
  end

  # ============================================================================
  # Code Generation
  # ============================================================================

  describe "code generation" do
    test "Some branch emits JEQ (null check) before body" do
      instructions = compile!("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(Some v) (bpf/load_u64 v 0)]
          [(None) 0]))
      """)

      # JEQ with imm=0 is the null check for the Some branch
      jeq_zero = Enum.filter(instructions, fn insn ->
        insn.opcode == @jeq_imm_opcode and insn.imm == 0
      end)
      assert length(jeq_zero) >= 1, "Some branch should emit JEQ reg, 0 (null check)"
    end

    test "None branch emits JNE before body" do
      instructions = compile!("""
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [fd :u64 key :u64] :u64
        (match (bpf/map_lookup_elem fd key)
          [(Some v) (bpf/load_u64 v 0)]
          [(None) 0]))
      """)

      # JNE with imm=0 is the null check for the None branch
      jne_zero = Enum.filter(instructions, fn insn ->
        insn.opcode == @jne_imm_opcode and insn.imm == 0
      end)
      assert length(jne_zero) >= 1, "None branch should emit JNE reg, 0 (non-null skip)"
    end

    test "full pipeline: defmap + lookup + null check + load" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn get_counter [key :u64] :u64
        (match (bpf/map_lookup_elem counters key)
          [(Some ptr) (bpf/load_u64 ptr 0)]
          [(None) 0]))
      """
      {:ok, instructions} = VaistoBpf.compile_source(source)
      decoded = Enum.map(instructions, &decode/1)

      # Should have CALL (map_lookup_elem)
      call_insn = Enum.find(decoded, &(&1.opcode == @call_opcode))
      assert call_insn != nil
      assert call_insn.imm == 1

      # Should have JEQ (null check for Some)
      jeq = Enum.any?(decoded, fn insn ->
        insn.opcode == @jeq_imm_opcode and insn.imm == 0
      end)
      assert jeq, "should have JEQ null check"

      # Should have LDX_MEM (load from non-null pointer in Some branch)
      ldx_opcode = Types.mem_dw() ||| Types.mem_mode() ||| Types.class_ldx()
      has_ldx = Enum.any?(decoded, &(&1.opcode == ldx_opcode and &1.offset == 0))
      assert has_ldx, "Some branch should load from pointer"
    end

    test "compiles to valid ELF" do
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn get_counter [key :u64] :u64
        (match (bpf/map_lookup_elem counters key)
          [(Some ptr) (bpf/load_u64 ptr 0)]
          [(None) 0]))
      """
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert <<0x7F, ?E, ?L, ?F, _rest::binary>> = elf
    end
  end

  # ============================================================================
  # Register Allocation
  # ============================================================================

  describe "register allocation" do
    test "null-check match doesn't overflow registers" do
      # Two sequential lookups with null checks — stresses register allocation
      source = """
      (defmap counters :hash :u32 :u64 1024)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)
      (defn f [key :u64] :u64
        (let [a (match (bpf/map_lookup_elem counters key)
                  [(Some v) (bpf/load_u64 v 0)]
                  [(None) 0])]
          (let [b (match (bpf/map_lookup_elem counters key)
                    [(Some v) (bpf/load_u64 v 0)]
                    [(None) 0])]
            (+ a b))))
      """
      assert {:ok, _} = VaistoBpf.compile_source(source)
    end
  end
end
