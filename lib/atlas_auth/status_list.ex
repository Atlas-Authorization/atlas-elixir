defmodule AtlasAuth.StatusList do
  @moduledoc """
  Verifier for the signed session status list (`GET /v1/sessions/revocations/status-list`).

  The list is a JWT (`typ: statuslist+jwt`) signed with the instance session key (RS256, PS256, ES256,
  ES384 or EdDSA, through `AtlasAuth.Verifier.verify_signed/3`). It carries the first `hash_bytes` bytes of
  the SHA-256 of every session id revoked in its window, sorted, as one base64url string.

      {:ok, list} = AtlasAuth.StatusList.verify(token, jwks_url: jwks_url, issuer: issuer)
      AtlasAuth.StatusList.has?(list, sid)
      list.truncated   # more sessions were revoked than fit: a miss proves nothing, use the feed

  Options: `:jwks_url` (required), `:issuer` (strongly recommended: without it any key in the JWKS may
  vouch for any issuer), `:fetcher`, `:cache` (as `AtlasAuth.Verifier`), `:now_ms`, `:skew_seconds` (30).
  Returns `{:error, reason}` with reason one of `:malformed`, `:unsupported`, `:no_key`, `:bad_signature`,
  `:bad_claims`, `:expired`; a list that does not verify is never used.
  """

  alias AtlasAuth.Verifier

  defstruct [:count, :truncated, :issued_at, :expires_at, :since, :hash_bytes, :hashes]

  @type t :: %__MODULE__{}

  @spec verify(String.t(), keyword()) :: {:ok, t()} | {:error, atom()}
  def verify(token, opts) when is_binary(token) do
    parts = String.split(token, ".")
    now_ms = opts[:now_ms] || System.system_time(:millisecond)
    skew = opts[:skew_seconds] || 30

    with true <- length(parts) == 3 and byte_size(token) <= 4_000_000 or {:error, :malformed},
         {:ok, header} <- decode_json(Enum.at(parts, 0)),
         :ok <- if(header["typ"] == "statuslist+jwt", do: :ok, else: {:error, :unsupported}),
         :ok <- if(header["alg"] in Verifier.signing_algs(), do: :ok, else: {:error, :unsupported}),
         {:ok, _h, claims} <- signed(token, parts, opts, now_ms),
         :ok <- claims_ok(claims, opts[:issuer], now_ms / 1000, skew),
         {:ok, hashes} <- Base.url_decode64(claims["h"] || "", padding: false) |> or_bad(),
         true <- byte_size(hashes) == claims["count"] * claims["hash_bytes"] or {:error, :bad_claims} do
      {:ok,
       %__MODULE__{
         count: claims["count"],
         truncated: claims["truncated"] == true,
         issued_at: claims["iat"] * 1000,
         expires_at: claims["exp"] * 1000,
         since: claims["since"],
         hash_bytes: claims["hash_bytes"],
         hashes: hashes
       }}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :malformed}
    end
  end

  def verify(_, _), do: {:error, :malformed}

  @doc "Whether the session id's hash is in the list (binary search)."
  @spec has?(t(), String.t()) :: boolean()
  def has?(%__MODULE__{count: count, hash_bytes: n, hashes: hashes}, sid) do
    <<needle::binary-size(n), _::binary>> = :crypto.hash(:sha256, sid)
    search(hashes, n, needle, 0, count - 1)
  end

  defp search(_h, _n, _needle, lo, hi) when lo > hi, do: false

  defp search(h, n, needle, lo, hi) do
    mid = div(lo + hi, 2)

    case :binary.part(h, mid * n, n) do
      ^needle -> true
      chunk when chunk < needle -> search(h, n, needle, mid + 1, hi)
      _ -> search(h, n, needle, lo, mid - 1)
    end
  end

  defp signed(token, parts, opts, now_ms) do
    vopts = [jwks_url: opts[:jwks_url], now_ms: now_ms] ++ Keyword.take(opts, [:fetcher, :cache])

    case Verifier.verify_signed(token, parts, vopts) do
      {:ok, header, claims} -> {:ok, header, claims}
      {:error, :no_keys} -> {:error, :no_key}
      {:error, _} -> {:error, :bad_signature}
    end
  end

  defp claims_ok(c, issuer, now_sec, skew) do
    cond do
      c["aud"] != "atlas:session-status-list" or c["token_use"] != "session_status_list" -> {:error, :bad_claims}
      issuer != nil and c["iss"] != issuer -> {:error, :bad_claims}
      not (is_number(c["exp"]) and is_number(c["iat"]) and is_number(c["since"])) -> {:error, :bad_claims}
      c["exp"] + skew < now_sec -> {:error, :expired}
      c["iat"] - skew > now_sec -> {:error, :bad_claims}
      not (is_integer(c["hash_bytes"]) and c["hash_bytes"] >= 4 and c["hash_bytes"] <= 32) -> {:error, :bad_claims}
      not (is_integer(c["count"]) and c["count"] >= 0) -> {:error, :bad_claims}
      not is_binary(c["h"]) -> {:error, :bad_claims}
      true -> :ok
    end
  end

  defp decode_json(b64) do
    with {:ok, json} <- Base.url_decode64(b64, padding: false),
         {:ok, %{} = m} <- Jason.decode(json) do
      {:ok, m}
    else
      _ -> {:error, :malformed}
    end
  end

  defp or_bad({:ok, v}), do: {:ok, v}
  defp or_bad(_), do: {:error, :bad_claims}
end
