defmodule AtlasAuth.KeyMirrorAssertionTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{ApiKeyAssertion, KeyMirror}
  alias AtlasAuth.KeyMirror.MemoryStore

  defmodule FakeApi do
    def create(_c, _body, _opts), do: Process.get(:row)
  end

  setup do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_pem} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()
    {_, private_pem} = JOSE.JWK.to_pem(jwk)

    row = %{
      "id" => "key_1", "subject_type" => "machine", "subject_id" => "m1", "scopes" => ["read", "write"],
      "credential" => "key_pair", "audience" => "ins_1", "public_key" => public_pem
    }

    Process.put(:row, {:ok, row})
    {:ok, store} = MemoryStore.start_link()
    {:ok, offset} = Agent.start_link(fn -> 0 end)

    mirror =
      KeyMirror.new(store: {MemoryStore, store}, api: FakeApi, now_ms: fn -> System.system_time(:millisecond) + Agent.get(offset, & &1) end)

    {:ok, _} = KeyMirror.mint(mirror, %{})
    {:ok, mirror: mirror, store: store, offset: offset, pem: private_pem}
  end

  defp sign(pem, opts \\ [], audience \\ "ins_1"), do: ApiKeyAssertion.sign(pem, "key_1", audience, opts)

  test "a valid assertion narrows scope", %{mirror: m, pem: pem} do
    assert {:ok, %{credential: "key_pair", jti: "a", effective_scopes: ["read"]}} =
             KeyMirror.verify_assertion(m, sign(pem, scope: "read", jti: "a"), required_scopes: ["read"])

    assert {:error, {:scope_not_granted, ["admin"]}} = KeyMirror.verify_assertion(m, sign(pem, scope: "admin"))
  end

  test "refusal codes, and the jti is claimed last", %{mirror: m, pem: pem, offset: offset} do
    assert {:error, :wrong_audience} = KeyMirror.verify_assertion(m, sign(pem, [], "other"))
    assert {:error, :assertion_expired} = KeyMirror.verify_assertion(m, sign(pem, ttl_seconds: -100))
    assert {:error, :assertion_lifetime_too_long} = KeyMirror.verify_assertion(m, sign(pem, ttl_seconds: 7200))
    assert {:error, :invalid_assertion} = KeyMirror.verify_assertion(m, "a.b.c")

    token = sign(pem, jti: "j1")
    assert {:error, {:insufficient_scope, ["nope"]}} = KeyMirror.verify_assertion(m, token, required_scopes: ["nope"])
    assert {:ok, _} = KeyMirror.verify_assertion(m, token)
    assert {:error, :assertion_replayed} = KeyMirror.verify_assertion(m, token)

    Agent.update(offset, fn _ -> -600_000 end)
    assert {:error, :assertion_not_yet_valid} = KeyMirror.verify_assertion(m, sign(pem))
  end

  test "disabled rows are refused and the webhook copies enabled", %{mirror: m, store: store, pem: pem} do
    held = MemoryStore.all(store) |> hd()
    MemoryStore.put(store, Map.put(held, :enabled, false))
    assert {:error, :invalid_assertion} = KeyMirror.verify_assertion(m, sign(pem))
    assert KeyMirror.apply_webhook(m, %{"type" => "api_key.updated", "data" => %{"id" => "key_1", "enabled" => true}})
    assert {:ok, _} = KeyMirror.verify_assertion(m, sign(pem))
    MemoryStore.mark_revoked(store, "key_1", 1, nil)
    assert {:error, :invalid} = KeyMirror.verify_assertion(m, sign(pem))
  end

  test "the secret path refuses a disabled row" do
    Process.put(:row, {:ok, %{"id" => "k2", "secret" => "ak_s", "enabled" => false}})
    {:ok, store} = MemoryStore.start_link()
    m = KeyMirror.new(store: {MemoryStore, store}, api: FakeApi)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert {:error, :invalid} = KeyMirror.verify(m, "ak_s")
    KeyMirror.apply_webhook(m, %{"type" => "api_key.updated", "data" => %{"id" => "k2", "enabled" => true}})
    assert {:ok, _} = KeyMirror.verify(m, "ak_s")
  end
end
