defmodule VaistoBpf.IR do
  @moduledoc """
  BPF Intermediate Representation — linear instruction nodes with symbolic labels.

  IR nodes represent BPF operations before register allocation and label resolution.
  The assembler converts these to concrete 8-byte BPF instructions.
  """

  @type register :: non_neg_integer()
  @type label :: atom() | {atom(), non_neg_integer()}

  @type instruction ::
          {:mov_imm, register(), integer()}
          | {:mov_reg, register(), register()}
          | {:alu64_imm, atom(), register(), integer()}
          | {:alu64_reg, atom(), register(), register()}
          | {:alu32_imm, atom(), register(), integer()}
          | {:alu32_reg, atom(), register(), register()}
          | {:jmp_imm, atom(), register(), integer(), label()}
          | {:jmp_reg, atom(), register(), register(), label()}
          | {:ja, label()}
          | {:label, label()}
          | {:call, non_neg_integer()}
          | {:ld_map_fd, register(), non_neg_integer()}
          | :exit

  @type program :: [instruction()]
end
