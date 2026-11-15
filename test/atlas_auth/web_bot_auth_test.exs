defmodule AtlasAuth.WebBotAuthTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.WebBotAuth, as: WBA
  alias AtlasAuth.WebBotAuth.DirectoryCache

  @now_ms 1_700_000_000_000
  @now div(@now_ms, 1000)
  @seed Base.decode16!("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
  @url "https://Site.example.com/pets?id=1&name=a%20b"
  @directory "https://bot.example"

  defp pub, do: elem(:crypto.generate_key(:eddsa, :ed25519, @seed), 0)
  defp jwk, do: %{"kty" => "OKP", "crv" => "Ed25519", "x" => Base.url_encode64(pub(), padding: false)}
  defp getter(keys \\ [jwk()]), do: fn _url, _refresh -> keys end

  defp signed(extra \\ []) do
    opts =
      Keyword.merge([method: "GET", url: @url, signature_agent: @directory, private_key: @seed, created: @now, expires: @now + 300], extra)

    headers = WBA.sign_request(opts)
    %{method: "GET", url: @url, headers: headers}
  end

  defp verify(req, extra \\ []), do: WBA.verify(req, [get_keys: getter(), now_ms: @now_ms] ++ extra)

  test "a signed request verifies and names its directory and key" do
    assert %{verified: true, signed: true, directory: @directory, label: "sig1", nonce: nil} = r = verify(signed())
    assert r.key_id == WBA.jwk_thumbprint(jwk())
  end

  test "components can be header members, query params and derived values" do
    comps = ["@authority", "signature-agent", "@method", "@path", "@query", {"@query-param", [{"name", "name"}]}, "@scheme", "@request-target"]
    assert %{verified: true} = verify(signed(components: comps))
  end

  test "an unsigned request is reported as such" do
    assert %{signed: false, verified: false, reason: :no_signature} = verify(%{method: "GET", url: @url, headers: []})
  end

  test "tampering with the host, method or signature fails" do
    req = signed()
    assert %{verified: false, reason: :bad_signature} = verify(%{req | url: "https://other.example.com/pets"})
    sig = req.headers["signature"]
    bad = %{req | headers: Map.put(req.headers, "signature", String.replace(sig, ":", ":AAAA", global: false))}
    assert %{verified: false} = verify(bad)
  end

  test "a missing @authority or signature-agent coverage is refused" do
    assert %{verified: false, reason: :components_not_covered} = verify(signed(components: ["signature-agent"]))
    assert %{verified: false, reason: :components_not_covered} = verify(signed(components: ["@authority"]))
  end

  test "time window: expired, not yet valid, too long" do
    assert %{reason: :expired} = verify(signed(created: @now - 1000, expires: @now - 500))
    assert %{reason: :not_yet_valid} = verify(signed(created: @now + 1000, expires: @now + 1500))
    assert %{reason: :lifetime_too_long} = verify(signed(created: @now, expires: @now + 4000))
    assert %{reason: :bad_params} = verify(signed(created: @now, expires: @now))
  end

  test "a key that is not in the directory, and an unreachable directory" do
    other = %{jwk() | "x" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)}
    assert %{verified: false, reason: :key_not_found} = WBA.verify(signed(), get_keys: getter([other]), now_ms: @now_ms)
    assert %{verified: false, reason: :directory_unavailable} = WBA.verify(signed(), get_keys: getter(nil), now_ms: @now_ms)
  end

  test "a refresh is asked for when the cached directory lacks the key" do
    {:ok, calls} = Agent.start_link(fn -> [] end)

    get = fn _url, refresh ->
      Agent.update(calls, &[refresh | &1])
      if refresh, do: [jwk()], else: []
    end

    assert %{verified: true} = WBA.verify(signed(), get_keys: get, now_ms: @now_ms)
    assert Agent.get(calls, &Enum.reverse/1) == [false, true]
  end

  test "nonce replay is refused only when a claim function is given" do
    {:ok, seen} = Agent.start_link(fn -> MapSet.new() end)

    claim = fn key, _exp ->
      Agent.get_and_update(seen, fn s -> if MapSet.member?(s, key), do: {false, s}, else: {true, MapSet.put(s, key)} end)
    end

    req = signed(nonce: "abc")
    assert %{verified: true, nonce: "abc"} = verify(req, claim_nonce: claim)
    assert %{verified: false, reason: :replayed} = verify(req, claim_nonce: claim)
    assert %{verified: true} = verify(req)
  end

  test "an alg other than ed25519 and a wrong tag are refused" do
    req = signed()
    alg = %{req | headers: Map.update!(req.headers, "signature-input", &String.replace(&1, "alg=\"ed25519\"", "alg=\"rsa-pss-sha512\""))}
    assert %{reason: :unsupported_algorithm} = verify(alg)
    tag = %{req | headers: Map.update!(req.headers, "signature-input", &String.replace(&1, "web-bot-auth", "other"))}
    assert %{reason: :no_web_bot_auth_signature} = verify(tag)
  end

  test "an sf-parameterised header component is refused (fail closed)" do
    assert_raise ArgumentError, fn -> signed(headers: %{"x-h" => "a"}, components: ["@authority", "signature-agent", {"x-h", [{"sf", true}]}]) end
  end

  test "the signature base follows RFC 9421" do
    req = %{method: "post", url: "https://example.com:8443/foo?param=Value&Pet=dog", headers: %{"Content-Type" => "application/json", "X-A" => ["1", " 2 "]}}

    assert {:ok, base} =
             WBA.build_signature_base(req, ["@method", "@authority", "@path", "@query", "content-type", "x-a", {"@query-param", [{"name", "Pet"}]}], "(sp)")

    assert base ==
             Enum.join(
               [
                 "\"@method\": POST",
                 "\"@authority\": example.com:8443",
                 "\"@path\": /foo",
                 "\"@query\": ?param=Value&Pet=dog",
                 "\"content-type\": application/json",
                 "\"x-a\": 1, 2",
                 "\"@query-param\";name=\"Pet\": dog",
                 "\"@signature-params\": (sp)"
               ],
               "\n"
             )

    assert {:error, :component_missing} = WBA.build_signature_base(req, ["x-missing"], "()")
    assert {:error, :unsupported_component} = WBA.build_signature_base(req, ["@method", "@method"], "()")
    assert {:error, :unsupported_component} = WBA.build_signature_base(req, ["Content-Type"], "()")
    assert {:error, :unsupported_component} = WBA.build_signature_base(req, ["@bogus"], "()")
    assert {:error, :bad_request} = WBA.build_signature_base(%{req | url: "not a url"}, ["@method"], "()")
  end

  test "parsers" do
    assert {:ok, [%{label: "sig1", components: [{"@authority", []}, {"signature-agent", [{"key", "a"}]}], params: params, raw: raw}]} =
             WBA.parse_signature_input(~s|sig1=("@authority" "signature-agent";key="a");created=1;keyid="k";tag="web-bot-auth"|)

    assert {"created", 1} in params and {"keyid", "k"} in params
    assert raw =~ "created=1"
    assert :error = WBA.parse_signature_input("garbage")
    assert {:ok, %{"sig1" => <<1, 2, 3>>}} = WBA.parse_signature_header("sig1=:AQID:")
    assert :error = WBA.parse_signature_header("sig1=AQID")

    assert WBA.parse_signature_agent(~s("https://Bot.Example/")) == "https://bot.example"
    assert WBA.parse_signature_agent("bot.example") == "https://bot.example"
    assert WBA.parse_signature_agent(~s(sig1="https://a.example", sig2="https://b.example"), "sig2") == "https://b.example"
    assert WBA.parse_signature_agent(~s(sig1="https://a.example", sig2="https://b.example"), "zzz") == "https://a.example"
    assert WBA.parse_signature_agent("http://bot.example") == nil
    assert WBA.parse_signature_agent("https://user:pw@bot.example") == nil
    assert WBA.parse_signature_agent("https://bot.example/x?y=1") == nil
    assert WBA.normalize_directory("https://bot.example:8443/dir/") == "https://bot.example:8443/dir"
    assert WBA.directory_url_for("https://bot.example") == "https://bot.example/.well-known/http-message-signatures-directory"
  end

  test "directory parsing keeps only well-formed Ed25519 keys" do
    good = jwk()
    assert WBA.parse_directory(%{"keys" => [good, %{"kty" => "RSA"}, %{"kty" => "OKP", "crv" => "Ed25519", "x" => "short"}]}) == [good]
    assert WBA.parse_directory(%{}) == []
    assert WBA.jwk_bytes(good) == pub()
  end

  test "the directory cache serves from cache, refreshes under a cooldown and keeps the last good copy" do
    {:ok, clock} = Agent.start_link(fn -> 0 end)
    {:ok, n} = Agent.start_link(fn -> 0 end)

    fetch = fn _url ->
      case Agent.get_and_update(n, &{&1, &1 + 1}) do
        0 -> {:ok, %{"keys" => [jwk()]}}
        _ -> :error
      end
    end

    {:ok, cache} = DirectoryCache.start_link(fetch_json: fetch, now_ms: fn -> Agent.get(clock, & &1) end)
    assert [_] = DirectoryCache.get_keys(cache, "u", false)
    assert [_] = DirectoryCache.get_keys(cache, "u", false)
    assert Agent.get(n, & &1) == 1
    # A forced refresh inside the cooldown is answered from cache.
    assert [_] = DirectoryCache.get_keys(cache, "u", true)
    assert Agent.get(n, & &1) == 1
    # After the cooldown the refresh runs, fails, and the last good copy is kept.
    Agent.update(clock, &(&1 + 61_000))
    assert [_] = DirectoryCache.get_keys(cache, "u", true)
    assert Agent.get(n, & &1) == 2
    # A directory never fetched successfully is nil.
    {:ok, bad} = DirectoryCache.start_link(fetch_json: fn _ -> :error end)
    assert DirectoryCache.get_keys(bad, "u", false) == nil
    assert is_function(DirectoryCache.getter(cache), 2)
  end
end
