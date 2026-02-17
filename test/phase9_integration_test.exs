defmodule VaistoBpf.Phase9IntegrationTest do
  use ExUnit.Case, async: true

  import Bitwise

  describe "end-to-end smoke test combining all Phase 9 features" do
    test "program type + ring buffer + helper calls + struct" do
      source = """
      (program :kprobe "do_sys_open")
      (deftype Event [ts :u64 pid :u64])
      (defmap events :ringbuf 0 0 4096)
      (extern bpf:ringbuf_reserve [:u64 :u64 :u64] :u64)
      (extern bpf:ringbuf_submit [:u64 :u64] :u64)
      (extern bpf:ktime_get_ns [] :u64)
      (extern bpf:get_current_pid_tgid [] :u64)

      (defn emit_event [] :u64
        (match (bpf/ringbuf_reserve events 16 0)
          [(Some ptr)
           (do (bpf/store_u64 ptr 0 (bpf/ktime_get_ns))
               (bpf/store_u64 ptr 8 (bpf/get_current_pid_tgid))
               (bpf/ringbuf_submit ptr 0)
               0)]
          [(None) 0]))
      """

      # Should compile to bytecode
      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) > 0

      # Should compile to ELF with kprobe section
      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert <<0x7F, "ELF", _rest::binary>> = elf
      assert :binary.match(elf, "kprobe/do_sys_open") != :nomatch
    end

    test "bounded loop with BPF-to-BPF call" do
      source = """
      (defn process_one [i :u64] :u64 (+ i 1))
      (defn main [n :u64] :u64
        (do (for-range i 0 n (process_one i))
            0))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) > 0

      # Should have both backward jump (loop) and pseudo-call
      decoded = Enum.map(instructions, &VaistoBpf.Types.decode/1)

      ja_opcode = VaistoBpf.Types.jmp_ja() ||| VaistoBpf.Types.class_jmp()
      has_backward_jump = Enum.any?(decoded, fn i ->
        i.opcode == ja_opcode and i.offset < 0
      end)
      assert has_backward_jump

      call_opcode = VaistoBpf.Types.jmp_call() ||| VaistoBpf.Types.class_jmp()
      has_pseudo_call = Enum.any?(decoded, fn i ->
        i.opcode == call_opcode and i.src == 1
      end)
      assert has_pseudo_call
    end

    test "struct field access through map lookup" do
      source = """
      (deftype Stats [count :u64 total :u64])
      (defmap store :hash :u64 :Stats 100)
      (extern bpf:map_lookup_elem [:u64 :u64] :u64)

      (defn read_count [key :u64] :u64
        (match (bpf/map_lookup_elem store key)
          [(Some ptr) (. ptr :count)]
          [(None) 0]))
      """

      {:ok, instructions} = VaistoBpf.compile_source(source)
      assert length(instructions) > 0
    end

    test "all features produce valid ELF" do
      source = """
      (program :xdp)
      (deftype Packet [len :u64])

      (defn classify [x :u64] :u64
        (if (> x 1500) 1 0))

      (defn handler [pkt_len :u64] :u64
        (classify pkt_len))
      """

      {:ok, elf} = VaistoBpf.compile_source_to_elf(source)
      assert <<0x7F, "ELF", _rest::binary>> = elf
      assert :binary.match(elf, "xdp") != :nomatch
    end
  end
end
