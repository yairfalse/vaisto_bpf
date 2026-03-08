defmodule VaistoBpf.ApplicationTest do
  use ExUnit.Case, async: true

  describe "runtime_available?/0" do
    test "returns boolean based on platform" do
      result = VaistoBpf.Application.runtime_available?()
      assert is_boolean(result)

      # On macOS CI this should be false
      case :os.type() do
        {:unix, :linux} -> assert result == true
        _ -> assert result == false
      end
    end
  end

  describe "compile_source_to_schema on any platform" do
    test "works without loader" do
      source = """
      (defn main [x :u64] :u64 x)
      """

      assert {:ok, schema} = VaistoBpf.compile_source_to_schema(source)
      assert is_binary(schema.elf_binary)
    end
  end
end
