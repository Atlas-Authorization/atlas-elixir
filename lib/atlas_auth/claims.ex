defmodule AtlasAuth.Claims do
  @moduledoc """
  The decoded, verified payload of an Atlas session JWT.

  Known claims are promoted to typed struct fields; the complete claim set —
  including anything a JWT template added that is not modelled here — is kept in
  `:raw`, so a caller never loses access to a custom claim.

  WHY the authorization helpers (`has_permission?/2`, `has_role?/2`) read
  straight off this struct and never call Atlas: putting `org_role` and
  `org_permissions` *in the token* is what lets a customer's hot path make an
  authorization decision with zero network round trips. The cost is that a
  permission change only takes effect on the next token mint — but that window is
  exactly the short token lifetime, the same bound as revocation, so it is a
  deliberate trade, not a gap.
  """

  @type t :: %__MODULE__{
          iss: String.t() | nil,
          sub: String.t() | nil,
          sid: String.t() | nil,
          exp: integer() | nil,
          nbf: integer() | nil,
          iat: integer() | nil,
          azp: String.t() | nil,
          sv: integer() | nil,
          mfa: boolean(),
          org_id: String.t() | nil,
          org_slug: String.t() | nil,
          org_role: String.t() | nil,
          org_permissions: [String.t()],
          external_id: String.t() | nil,
          raw: map()
        }

  defstruct iss: nil,
            sub: nil,
            sid: nil,
            exp: nil,
            nbf: nil,
            iat: nil,
            azp: nil,
            sv: nil,
            mfa: false,
            org_id: nil,
            org_slug: nil,
            org_role: nil,
            org_permissions: [],
            external_id: nil,
            raw: %{}

  @doc """
  Build a `%Claims{}` from the raw, string-keyed claim map produced by the
  verifier. Unknown keys survive in `:raw`.
  """
  @spec from_map(map()) :: t()
  def from_map(raw) when is_map(raw) do
    %__MODULE__{
      iss: raw["iss"],
      sub: raw["sub"],
      sid: raw["sid"],
      exp: as_int(raw["exp"]),
      nbf: as_int(raw["nbf"]),
      iat: as_int(raw["iat"]),
      azp: raw["azp"],
      sv: as_int(raw["sv"]),
      mfa: raw["mfa"] == true,
      org_id: raw["org_id"],
      org_slug: raw["org_slug"],
      org_role: raw["org_role"],
      org_permissions: string_list(raw["org_permissions"]),
      external_id: if(is_binary(raw["external_id"]), do: raw["external_id"]),
      raw: raw
    }
  end

  @doc """
  True when `org_permissions` contains `permission`. Reads the claim; never a
  network call.
  """
  @spec has_permission?(t(), String.t()) :: boolean()
  def has_permission?(%__MODULE__{org_permissions: perms}, permission),
    do: permission in perms

  @doc "True when the session's `org_role` equals `role`."
  @spec has_role?(t(), String.t()) :: boolean()
  def has_role?(%__MODULE__{org_role: role}, role) when is_binary(role), do: true
  def has_role?(%__MODULE__{}, _role), do: false

  @doc """
  True when the `app_roles` claim (the user's instance-wide app roles) contains
  `role`. Needs no active organization.
  """
  @spec has_app_role?(t(), String.t()) :: boolean()
  def has_app_role?(%__MODULE__{raw: raw}, role), do: role in string_list(raw["app_roles"])

  @doc """
  True when the `app_permissions` claim (the union of the user's app roles'
  permissions) contains `permission`. Needs no active organization.
  """
  @spec has_app_permission?(t(), String.t()) :: boolean()
  def has_app_permission?(%__MODULE__{raw: raw}, permission),
    do: permission in string_list(raw["app_permissions"])

  defp string_list(list) when is_list(list), do: Enum.filter(list, &is_binary/1)
  defp string_list(_), do: []

  defp as_int(n) when is_integer(n), do: n
  defp as_int(n) when is_float(n), do: trunc(n)
  defp as_int(_), do: nil
end
