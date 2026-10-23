defmodule AtlasAuth.BotId do
  @moduledoc """
  Vercel BotID for Atlas: the signing half that runs next to your BotID check.

  BotID's verdict (`checkBotId()`) only exists inside a Vercel-hosted request,
  so that route turns it into a short signed attestation; the browser sends it
  to Atlas as `captcha_token`, and Atlas checks the signature, freshness and
  `is_bot == false`, and spends it (each attestation passes once). The same
  secret is stored in Atlas for the `vercel_botid` captcha provider.

  Format (version 1): `atlas_botid.v1.<payload>.<sig>` — `payload` is base64url
  JSON `{v: 1, is_bot, verified_bot, iat, exp, jti}`; `sig` is base64url
  HMAC-SHA256 over `atlas_botid.v1.<payload>` keyed by the shared secret.
  """

  @prefix "atlas_botid.v1."
  @max_ttl 300
  @min_secret 32

  def prefix, do: @prefix
  def max_ttl_seconds, do: @max_ttl
  def secret_min_length, do: @min_secret

  @doc """
  Sign a BotID verdict. Options: `:verified_bot` (default false), `:ttl_seconds`
  (default 60, clamped to 1–300), `:now` (UNIX seconds). Returns
  `{:error, :secret_too_short}` for a secret under 32 characters. A bot verdict
  is still signed — Atlas refuses it.
  """
  @spec create_attestation(String.t(), boolean(), keyword()) ::
          {:ok, String.t()} | {:error, :secret_too_short}
  def create_attestation(secret, is_bot, opts \\ []) do
    if not is_binary(secret) or String.length(secret) < @min_secret do
      {:error, :secret_too_short}
    else
      ttl = opts |> Keyword.get(:ttl_seconds, 60) |> max(1) |> min(@max_ttl)
      iat = Keyword.get(opts, :now, System.system_time(:second))

      payload =
        %{
          v: 1,
          is_bot: is_bot == true,
          verified_bot: Keyword.get(opts, :verified_bot, false) == true,
          iat: iat,
          exp: iat + ttl,
          jti: Base.url_encode64(:crypto.strong_rand_bytes(18), padding: false)
        }
        |> Jason.encode!()
        |> Base.url_encode64(padding: false)

      sig =
        :crypto.mac(:hmac, :sha256, secret, @prefix <> payload)
        |> Base.url_encode64(padding: false)

      {:ok, @prefix <> payload <> "." <> sig}
    end
  end
end
