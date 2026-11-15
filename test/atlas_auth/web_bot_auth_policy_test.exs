defmodule AtlasAuth.WebBotAuthPolicyTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.WebBotAuth, as: WBA
  alias AtlasAuth.WebBotAuth.Verifier

  @now_ms 1_700_000_000_000
  @now div(@now_ms, 1000)
  @seed Base.decode16!("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
  @url "https://site.example.com/pets"
  @directory "https://bot.example"

  defp jwk, do: %{"kty" => "OKP", "crv" => "Ed25519", "x" => Base.url_encode64(elem(:crypto.generate_key(:eddsa, :ed25519, @seed), 0), padding: false)}

  defp signed(extra \\ []) do
    headers = WBA.sign_request(Keyword.merge([method: "GET", url: @url, signature_agent: @directory, private_key: @seed, created: @now, expires: @now + 300], extra))
    %{method: "GET", url: @url, headers: headers}
  end

  defp verified_result do
    WBA.verify(signed(), get_keys: fn _, _ -> [jwk()] end, now_ms: @now_ms)
  end

  describe "decide/2" do
    test "a verified directory is allowed, blocked or unknown by the lists; block beats allow" do
      r = verified_result()
      assert %{decision: :unknown, tier: :verified, agent: %{directory: @directory, name: "bot.example"}} = WBA.decide(r)
      assert %{decision: :allow, tier: :allowed, agent: %{name: "Example"}} = WBA.decide(r, allow: [%{directory: "bot.example", name: "Example"}])
      assert %{decision: :block, tier: :blocked} = WBA.decide(r, allow: [@directory], block: ["https://BOT.example/"])
      assert %{decision: :unknown} = WBA.decide(r, allow: ["https://other.example"])
    end

    test "an unsigned or failed request is unknown and never attributed" do
      unsigned = WBA.verify(%{method: "GET", url: @url, headers: []}, get_keys: fn _, _ -> [] end)
      assert %{verified: false, agent: nil, tier: :unverified, decision: :unknown, reason: :no_signature} = WBA.decide(unsigned, allow: [@directory])
      bad = WBA.verify(%{signed() | url: "https://elsewhere.example/"}, get_keys: fn _, _ -> [jwk()] end, now_ms: @now_ms)
      assert %{agent: nil, decision: :unknown} = WBA.decide(bad, block: [@directory])
    end
  end

  describe "Verifier" do
    test "verifies with a cached directory and applies the policy" do
      {:ok, v} = Verifier.start_link(allow: [@directory], fetch_json: fn _ -> {:ok, %{"keys" => [jwk()]}} end, now_ms: fn -> @now_ms end)
      assert %{decision: :allow, verified: true} = Verifier.verify(v, signed())
      assert %{decision: :unknown, verified: false} = Verifier.verify(v, %{method: "GET", url: @url, headers: []})
    end

    test "an unreachable directory is unverified" do
      {:ok, v} = Verifier.start_link(fetch_json: fn _ -> :error end, now_ms: fn -> @now_ms end)
      assert %{verified: false, reason: :directory_unavailable} = Verifier.verify(v, signed())
    end

    test "replays are refused only with reject_replays" do
      fetch = fn _ -> {:ok, %{"keys" => [jwk()]}} end
      req = signed(nonce: "n1")
      {:ok, off} = Verifier.start_link(fetch_json: fetch, now_ms: fn -> @now_ms end)
      assert %{verified: true} = Verifier.verify(off, req)
      assert %{verified: true} = Verifier.verify(off, req)
      {:ok, on} = Verifier.start_link(fetch_json: fetch, now_ms: fn -> @now_ms end, reject_replays: true)
      assert %{verified: true} = Verifier.verify(on, req)
      assert %{verified: false, reason: :replayed} = Verifier.verify(on, req)
    end
  end
end
