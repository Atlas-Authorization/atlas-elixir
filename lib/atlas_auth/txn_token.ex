defmodule AtlasAuth.TxnToken do
  @moduledoc """
  Verify a Transaction Token (draft-ietf-oauth-transaction-tokens) a service received:
  `typ` `txntoken+jwt`, signed by the issuer's keys, for THIS trust domain,
  unexpired, with the required claims (`txn`, `sub`, `scope`, `req_wl`, `iat`, `exp`).
  A recipient must refuse a token whose `aud` is not its own trust domain.

      case AtlasAuth.TxnToken.verify(token, issuer: "https://id.example.com", trust_domain: "payments.example.com") do
        {:ok, %{claims: claims, scopes: scopes}} -> ...
        {:error, _} -> refuse
      end

  Options: `:issuer` and `:trust_domain` (required); `:jwks_url` (default
  `<issuer>/.well-known/jwks.json`); `:now_ms`, `:cache` and `:fetcher` as for
  `AtlasAuth.Verifier`. Clock tolerance is 5 seconds.
  """

  @tolerance 5
  @required ~w(txn sub scope req_wl iat exp)

  @type reason :: :malformed | :invalid | {:missing_claim, String.t()} | atom()

  @spec verify(String.t(), keyword()) :: {:ok, %{claims: map(), scopes: [String.t()]}} | {:error, reason()}
  def verify(token, opts) when is_binary(token) do
    issuer = opts |> Keyword.fetch!(:issuer) |> String.trim_trailing("/")
    trust_domain = Keyword.fetch!(opts, :trust_domain)
    now_ms = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    parts = String.split(token, ".")
    jwks_url = Keyword.get(opts, :jwks_url, issuer <> "/.well-known/jwks.json")
    verify_opts = opts |> Keyword.take([:cache, :fetcher]) |> Keyword.merge(jwks_url: jwks_url, now_ms: now_ms)

    with {:ok, header, claims} <- AtlasAuth.Verifier.verify_signed(token, parts, verify_opts),
         :ok <- check(header["typ"] == "txntoken+jwt"),
         :ok <- check(claims["iss"] == issuer),
         :ok <- check(audience?(claims["aud"], trust_domain)),
         :ok <- check_time(claims, div(now_ms, 1000)),
         :ok <- required(claims) do
      {:ok, %{claims: claims, scopes: claims["scope"] |> to_string() |> String.split(" ", trim: true)}}
    end
  end

  def verify(_token, _opts), do: {:error, :malformed}

  defp check(true), do: :ok
  defp check(_), do: {:error, :invalid}

  defp audience?(aud, domain) when is_binary(aud), do: aud == domain
  defp audience?(aud, domain) when is_list(aud), do: domain in aud
  defp audience?(_, _), do: false

  defp check_time(claims, now) do
    exp = claims["exp"]
    nbf = claims["nbf"]

    cond do
      not is_number(exp) -> {:error, {:missing_claim, "exp"}}
      exp + @tolerance <= now -> {:error, :invalid}
      is_number(nbf) and nbf - @tolerance > now -> {:error, :invalid}
      is_number(claims["iat"]) and claims["iat"] - @tolerance > now -> {:error, :invalid}
      true -> :ok
    end
  end

  defp required(claims) do
    case Enum.find(@required, &is_nil(claims[&1])) do
      nil -> :ok
      name -> {:error, {:missing_claim, name}}
    end
  end
end
