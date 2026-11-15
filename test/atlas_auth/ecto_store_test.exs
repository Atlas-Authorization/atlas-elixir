defmodule AtlasAuth.WebhookDedupe.EctoStoreTest do
  use ExUnit.Case, async: true

  # No database in the unit run: a fake repo module stands in for `Ecto.Adapters.SQL.query/3`'s target is not
  # possible, so this test runs only when :ecto_sql is installed and checks the dialect SQL through a recording Ecto adapter
  # is out of scope; it asserts the module's contract instead.
  if Code.ensure_loaded?(Ecto.Adapters.SQL) do
    test "implements the store behaviour" do
      behaviours = AtlasAuth.WebhookDedupe.EctoStore.module_info(:attributes)[:behaviour] || []
      assert AtlasAuth.WebhookDedupe in behaviours
      assert function_exported?(AtlasAuth.WebhookDedupe.EctoStore, :set_if_absent, 3)
      assert function_exported?(AtlasAuth.WebhookDedupe.EctoStore, :delete, 2)
    end
  else
    test "is not compiled without :ecto_sql" do
      refute Code.ensure_loaded?(AtlasAuth.WebhookDedupe.EctoStore)
    end
  end
end
