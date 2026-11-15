defmodule AtlasAuth.MachineClientTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.MachineClient
  alias AtlasAuth.MachineClient.{Error, MemoryStore}

  # The RFC 8032 test 1 key: private seed 9d61b19d..., public d75a9801...
  @private_pem "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
  @public_pem "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
  @rfc8032_test1_sig "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
  @issuer "https://id.example.com"

  test "the challenge signature is pure Ed25519 over the nonce bytes, base64url (RFC 8032 vector)" do
    assert MachineClient.sign_challenge(@private_pem, "") == Base.url_encode64(Base.decode16!(@rfc8032_test1_sig, case: :lower), padding: false)
    nonce = "n-123"
    sig = MachineClient.sign_challenge(@private_pem, nonce) |> Base.url_decode64!(padding: false)
    {pub, _} = :crypto.generate_key(:eddsa, :ed25519, Base.decode16!("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60"))
    assert :crypto.verify(:eddsa, :none, nonce, sig, [pub, :ed25519])
    refute :crypto.verify(:eddsa, :none, nonce <> "x", sig, [pub, :ed25519])
  end

  test "public_key_pem_of re-derives the SPKI the server holds" do
    assert MachineClient.public_key_pem_of(@private_pem) == @public_pem
  end

  test "generate_keypair makes a consistent PEM pair" do
    {pub, priv} = MachineClient.generate_keypair()
    assert pub =~ "BEGIN PUBLIC KEY"
    assert priv =~ "BEGIN PRIVATE KEY"
    assert MachineClient.public_key_pem_of(priv) == pub
  end

  defp raw_pub(pem) do
    der = pem |> String.split("\n", trim: true) |> Enum.reject(&String.starts_with?(&1, "-----")) |> Enum.join() |> Base.decode64!()
    binary_part(der, byte_size(der) - 32, 32)
  end

  # A scripted server: records requests, answers by path.
  defp server(handlers) do
    {:ok, calls} = Agent.start_link(fn -> [] end)

    poster = fn url, headers, body ->
      path = URI.parse(url).path
      Agent.update(calls, &[%{path: path, headers: headers, body: Jason.decode!(body)} | &1])
      {status, json} = handlers.(path, Agent.get(calls, &length/1))
      {:ok, status, Jason.encode!(json)}
    end

    {poster, fn -> Agent.get(calls, &Enum.reverse/1) end}
  end

  defp start(poster, extra \\ []) do
    {:ok, store} = MemoryStore.start_link()
    {:ok, clock} = Agent.start_link(fn -> 1_000_000 end)
    {:ok, pid} = MachineClient.start_link([issuer: @issuer <> "/", store: {MemoryStore, store}, poster: poster, now_ms: fn -> Agent.get(clock, & &1) end] ++ extra)
    {pid, store, clock}
  end

  test "enrol stores an identity whose public key matches, then mints tokens with a valid signature, caching them" do
    {poster, calls} =
      server(fn
        "/v1/machines/enroll", _ -> {201, %{"id" => "mch_1", "status" => "active", "approval_required" => false, "enrolled_at" => 5}}
        "/v1/machines/challenge", _ -> {200, %{"nonce" => "nonce-1"}}
        "/v1/machines/token", n -> {200, %{"token" => "tok-#{n}", "expires_in" => 300}}
      end)

    {pid, store, clock} = start(poster)
    refute MachineClient.enrolled?(pid)
    assert {:error, %Error{code: "not_enrolled"}} = MachineClient.get_token(pid)

    assert {:ok, %{machine_id: "mch_1", approval_required: false}} = MachineClient.enroll(pid, credential: " met_abc ", name: "worker")
    assert MachineClient.enrolled?(pid)
    id = MemoryStore.load(store)
    assert id["issuer"] == @issuer
    assert MachineClient.public_key_pem_of(id["private_key_pem"]) == id["public_key_pem"]

    [enrol] = calls.()
    assert enrol.body["enrolment_token"] == "met_abc"
    assert enrol.body["public_key_pem"] == id["public_key_pem"]
    refute Map.has_key?(enrol.body, "private_key_pem")

    assert {:ok, %{token: t1, token_type: "Bearer"}} = MachineClient.get_token(pid, audience: "api")
    # Cached: no new calls.
    assert {:ok, %{token: ^t1}} = MachineClient.get_token(pid, audience: "api")
    token_calls = Enum.filter(calls.(), &(&1.path == "/v1/machines/token"))
    assert length(token_calls) == 1
    [%{body: body}] = token_calls
    assert body["machine_id"] == "mch_1"
    assert body["audience"] == "api"
    sig = Base.url_decode64!(body["signature"], padding: false)
    pub = raw_pub(id["public_key_pem"])
    assert :crypto.verify(:eddsa, :none, "nonce-1", sig, [pub, :ed25519])

    # A different audience, and a different scope order that normalises to one entry.
    assert {:ok, %{token: t2}} = MachineClient.get_token(pid, audience: "other")
    refute t2 == t1
    {:ok, %{token: t3}} = MachineClient.get_token(pid, audience: "api", scopes: ["b", "a"])
    assert {:ok, %{token: ^t3}} = MachineClient.get_token(pid, audience: "api", scopes: ["a", "b"])

    # Refreshed inside the skew window.
    Agent.update(clock, &(&1 + 250_000))
    assert {:ok, %{token: t4}} = MachineClient.get_token(pid, audience: "api")
    refute t4 == t1
  end

  test "an identity of another issuer is ignored" do
    {poster, _} = server(fn _, _ -> {200, %{}} end)
    {:ok, store} = MemoryStore.start_link(%{"issuer" => "https://other.example.com", "machine_id" => "m", "private_key_pem" => @private_pem})
    {:ok, pid} = MachineClient.start_link(issuer: @issuer, store: {MemoryStore, store}, poster: poster)
    refute MachineClient.enrolled?(pid)
  end

  test "server errors carry status and code; reset forgets the identity" do
    {poster, _} = server(fn _, _ -> {403, %{"errors" => [%{"code" => "ENROLMENT_TOKEN_USED", "message" => "used"}]}} end)
    {pid, _store, _} = start(poster)
    assert {:error, %Error{status: 403, code: "ENROLMENT_TOKEN_USED", message: "used"}} = MachineClient.enroll(pid, credential: "met_x", name: "n")

    {ok_poster, _} = server(fn "/v1/machines/enroll", _ -> {201, %{"id" => "mch_1", "status" => "pending", "approval_required" => true}} end)
    {pid2, _, _} = start(ok_poster)
    assert {:ok, %{approval_required: true}} = MachineClient.enroll(pid2, credential: "met_x", name: "n")
    assert MachineClient.enrolled?(pid2)
    :ok = MachineClient.reset(pid2)
    refute MachineClient.enrolled?(pid2)
  end

  test "a DPoP-bound client sends a proof with the token request and signs proofs for API calls" do
    {poster, calls} =
      server(fn
        "/v1/machines/enroll", _ -> {201, %{"id" => "mch_1", "status" => "active", "approval_required" => false}}
        "/v1/machines/challenge", _ -> {200, %{"nonce" => "n"}}
        "/v1/machines/token", _ -> {200, %{"token" => "tok", "token_type" => "DPoP", "expires_in" => 300}}
      end)

    {pid, _, _} = start(poster, dpop_key: :generate)
    {:ok, _} = MachineClient.enroll(pid, credential: "met_x", name: "n")
    assert {:ok, %{token: "tok", token_type: "DPoP"}} = MachineClient.get_token(pid)
    token_call = Enum.find(calls.(), &(&1.path == "/v1/machines/token"))
    {"dpop", proof} = List.keyfind(token_call.headers, "dpop", 0)
    [h, p, _sig] = String.split(proof, ".")
    header = h |> Base.url_decode64!(padding: false) |> Jason.decode!()
    claims = p |> Base.url_decode64!(padding: false) |> Jason.decode!()
    assert header["typ"] == "dpop+jwt" and header["alg"] == "EdDSA"
    assert claims["htm"] == "POST" and claims["htu"] == @issuer <> "/v1/machines/token"
    assert AtlasAuth.DPoP.jwk_thumbprint(header["jwk"]) == MachineClient.dpop_thumbprint(pid)

    assert {:ok, api_proof} = MachineClient.dpop_proof(pid, token: "tok", method: "get", url: "https://api.example.com/x?y=1", nonce: "srv")
    [_, p2, _] = String.split(api_proof, ".")
    c2 = p2 |> Base.url_decode64!(padding: false) |> Jason.decode!()
    assert c2["htm"] == "GET" and c2["ath"] == AtlasAuth.DPoP.access_token_hash("tok") and c2["nonce"] == "srv"
  end

  for {label, key, alg, crv, size} <- [{"P-256", {:generate, :es256}, "ES256", "P-256", 32}, {"P-384", {:generate, :es384}, "ES384", "P-384", 48}] do
    test "#{label} DPoP proofs are raw r||s signatures that verify against the jwk" do
      {poster, _calls} = server(fn _, _ -> {200, %{}} end)
      {pid, _, _} = start(poster, dpop_key: unquote(Macro.escape(key)))
      assert {:ok, proof} = MachineClient.dpop_proof(pid, token: "tok", method: "post", url: "https://api.example.com/x")
      [h, p, sig] = String.split(proof, ".")
      header = h |> Base.url_decode64!(padding: false) |> Jason.decode!()
      assert header["alg"] == unquote(alg) and header["jwk"]["crv"] == unquote(crv)
      raw = Base.url_decode64!(sig, padding: false)
      assert byte_size(raw) == 2 * unquote(size)
      <<r::binary-size(unquote(size)), sv::binary-size(unquote(size))>> = raw
      der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", :binary.decode_unsigned(r), :binary.decode_unsigned(sv)})
      jwk = JOSE.JWK.from_map(header["jwk"])
      assert {true, _, _} = JOSE.JWS.verify_strict(jwk, [unquote(alg)], proof)
      assert is_binary(der)
      assert AtlasAuth.DPoP.jwk_thumbprint(header["jwk"]) == MachineClient.dpop_thumbprint(pid)
      assert p != ""
    end
  end

  test "a PEM EC key is accepted and an unsupported key is refused" do
    pem = MachineClient.generate_dpop_key(:es256)
    {poster, _} = server(fn _, _ -> {200, %{}} end)
    {pid, _, _} = start(poster, dpop_key: pem)
    assert {:ok, _} = MachineClient.dpop_proof(pid, token: "t", method: "GET", url: "https://a.example/")
    Process.flag(:trap_exit, true)
    assert_raise MatchError, fn -> start(poster, dpop_key: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n") end
  end

  test "without a dpop key proofs are refused and there is no thumbprint" do
    {poster, _} = server(fn _, _ -> {200, %{}} end)
    {pid, _, _} = start(poster)
    assert {:error, %Error{code: "dpop_not_configured"}} = MachineClient.dpop_proof(pid, token: "t", method: "GET", url: "https://a.example/")
    assert MachineClient.dpop_thumbprint(pid) == nil
  end

  test "the file store is written 0600 and round-trips" do
    path = Path.join(System.tmp_dir!(), "atlas-machine-#{System.unique_integer([:positive])}/identity.json")
    on_exit(fn -> File.rm_rf!(Path.dirname(path)) end)
    id = %{"issuer" => @issuer, "machine_id" => "mch_1", "private_key_pem" => @private_pem, "public_key_pem" => @public_pem, "enrolled_at" => 1}
    :ok = MachineClient.FileStore.save(path, id)
    assert MachineClient.FileStore.load(path) == id
    {:ok, %File.Stat{mode: mode}} = File.stat(path)
    assert Bitwise.band(mode, 0o777) == 0o600
    :ok = MachineClient.FileStore.clear(path)
    assert MachineClient.FileStore.load(path) == nil
  end
end
