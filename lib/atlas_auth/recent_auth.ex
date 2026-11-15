defmodule AtlasAuth.RecentAuth do
  @moduledoc """
  Step-up checks on a verified Atlas token. Session and template tokens carry `auth_time`
  (the first-factor sign-in, or the last step-up), `amr` and `acr` (`urn:atlas:acr:basic`,
  `urn:atlas:acr:mfa`, `urn:atlas:acr:step_up`).

      {:ok, claims} = AtlasAuth.Verifier.verify(token, opts)

      if AtlasAuth.RecentAuth.authenticated_within?(claims, 300) do
        :ok
      else
        # Ask the browser to step up (POST /v1/client/me/step_up) and retry.
        {:error, :reauthentication_required}
      end

  Every function takes an `%AtlasAuth.Claims{}` or the raw string-keyed claim map.
  """

  @mfa_acr "urn:atlas:acr:mfa"

  @doc "Whether `auth_time` is within `max_age_seconds` of now. A token without `auth_time` never is."
  @spec authenticated_within?(struct() | map(), number(), integer()) :: boolean()
  def authenticated_within?(claims, max_age_seconds, now_ms \\ System.system_time(:millisecond)) do
    case get(claims, "auth_time") do
      at when is_number(at) -> now_ms / 1000 - at <= max_age_seconds
      _ -> false
    end
  end

  @doc "Whether the session proved a second factor (`acr` is mfa, or `amr` includes `mfa`)."
  @spec used_multi_factor?(struct() | map()) :: boolean()
  def used_multi_factor?(claims) do
    get(claims, "acr") == @mfa_acr or (is_list(get(claims, "amr")) and "mfa" in get(claims, "amr"))
  end

  @doc """
  Whether the session satisfies a "requires MFA" rule, in order: `mfa_satisfied` (the server's own
  verdict, final whenever the token carries it); else `mfa` is true, or `used_multi_factor?/1`, or
  `sso_connection_id` is a string (an enterprise SSO sign-in: the identity provider owns the second factor).
  """
  @spec mfa_satisfied?(struct() | map()) :: boolean()
  def mfa_satisfied?(claims) do
    case get(claims, "mfa_satisfied") do
      v when is_boolean(v) -> v
      _ -> get(claims, "mfa") == true or used_multi_factor?(claims) or is_binary(get(claims, "sso_connection_id"))
    end
  end

  @doc """
  Whether the session meets the active organization's MFA policy: true when the organization does not require
  MFA, or the token says `org_mfa_ok`. The claims describe the ACTIVE organization only: pass the organization
  you are authorizing for (its Atlas id or external id) and a token whose active organization is another one
  answers false. An app that authorizes from its own tables must call this itself: the policy only withholds
  org claims from the token.
  """
  @spec mfa_org_satisfied?(struct() | map(), String.t() | nil) :: boolean()
  def mfa_org_satisfied?(claims, org_id_or_external_id \\ nil) do
    required = get(claims, "org_mfa_required") == true

    if org_id_or_external_id == nil do
      not required or get(claims, "org_mfa_ok") == true
    else
      matches = get(claims, "org_id") == org_id_or_external_id or get(claims, "org_external_id") == org_id_or_external_id
      # Withheld claims carry no org_id: the MFA fields are then all the token says.
      if required, do: get(claims, "org_mfa_ok") == true and (matches or get(claims, "org_id") == nil), else: matches
    end
  end

  defp get(%AtlasAuth.Claims{raw: raw}, key), do: Map.get(raw, key)
  defp get(map, key) when is_map(map), do: Map.get(map, key)
end
