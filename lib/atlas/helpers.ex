defmodule Atlas.Helpers do
  @moduledoc """
  Small, validated helpers over the generated Backend API modules.

  * `rotate_events_secret/4` - rotate an integration's event-receiver signing secret.
  * `jwt_template_settings/1` - build and validate the `settings` map of a JWT template.
  """

  @max_overlap 604_800

  @doc """
  Rotate the signing secret of an integration's event receiver (`POST /v1/instance/integrations/{product}/events_secret/rotate`).
  The new secret is revealed exactly once. With `:overlap_seconds` (0 to #{@max_overlap}) the old secret keeps signing every
  delivery as a second `Atlas-Signature` entry until `previous_secret_expires_at`, so your receiver can verify with either while
  it deploys the new one. Returns `{:ok, %{"secret" => ..., "overlap_seconds" => ..., "previous_secret_expires_at" => ...}}`.
  """
  @spec rotate_events_secret(Atlas.Client.t(), String.t(), keyword(), keyword()) :: {:ok, map()} | {:error, term()}
  def rotate_events_secret(client, product, params \\ [], opts \\ []) do
    overlap = params[:overlap_seconds]

    if overlap != nil and not (is_integer(overlap) and overlap >= 0 and overlap <= @max_overlap) do
      {:error, {:invalid, "overlap_seconds must be a whole number from 0 to #{@max_overlap}"}}
    else
      body = if overlap == nil, do: %{}, else: %{overlap_seconds: overlap}
      Atlas.Instance.post_integrations_events_secret_rotate(client, product, body, opts)
    end
  end

  @doc """
  Per-template mint settings for `Atlas.JwtTemplates.create/3` and `update/4` (`%{settings: jwt_template_settings(...)}`).
  Options: `:lifetime_seconds` (10 to 86400, or `nil` to clear on update; default: the instance session-token lifetime),
  `:audience` (string or `nil`), `:algorithm` (`"RS256"` or `"HS256"`), `:signing_secret` (HS256 shared secret, at least
  16 characters, write-only). Returns `{:ok, map}` or `{:error, {:invalid, message}}`.
  """
  @spec jwt_template_settings(keyword()) :: {:ok, map()} | {:error, {:invalid, String.t()}}
  def jwt_template_settings(opts) do
    with :ok <- check_lifetime(Keyword.get(opts, :lifetime_seconds, :unset)),
         :ok <- check_alg(opts[:algorithm]),
         :ok <- check_secret(opts[:signing_secret], opts[:algorithm]) do
      {:ok, for({k, v} <- opts, k in [:lifetime_seconds, :audience, :algorithm, :signing_secret], into: %{}, do: {k, v})}
    end
  end

  defp check_lifetime(:unset), do: :ok
  defp check_lifetime(nil), do: :ok
  defp check_lifetime(n) when is_integer(n) and n >= 10 and n <= 86_400, do: :ok
  defp check_lifetime(_), do: {:error, {:invalid, "lifetime_seconds must be 10 to 86400 (or nil to clear)"}}

  defp check_alg(nil), do: :ok
  defp check_alg(a) when a in ["RS256", "HS256"], do: :ok
  defp check_alg(_), do: {:error, {:invalid, "algorithm must be RS256 or HS256"}}

  defp check_secret(nil, _), do: :ok
  defp check_secret(s, alg) when is_binary(s) and byte_size(s) >= 16 and alg in [nil, "HS256"], do: :ok
  defp check_secret(_, _), do: {:error, {:invalid, "signing_secret needs algorithm HS256 and at least 16 characters"}}
end
