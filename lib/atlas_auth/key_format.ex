defmodule AtlasAuth.KeyFormat do
  @moduledoc """
  Classify Atlas credentials by prefix.

  Atlas keys come in two formats. The suite format is
  `atlas_<live|test>_<kind>_<random><checksum>` (`sk`, `psk`, `dsk`, `whsec`,
  `pl`, `at`); the legacy format is `sk_live_...`, `sk_test_...`, `pk_...`,
  `psk_...`, `whsec_...` and `dsk_...`. Any prefix check in your code must
  accept both, which is what these helpers do. They do not validate a checksum
  or contact Atlas.

      iex> AtlasAuth.KeyFormat.secret_key?("atlas_live_sk_abc123")
      true
      iex> AtlasAuth.KeyFormat.secret_key?("sk_test_abc123")
      true
      iex> AtlasAuth.KeyFormat.parse("pk_live_x")
      {:ok, %{kind: :publishable, environment: "live", suite: false}}
  """

  @type kind :: :secret | :platform | :publishable | :deploy | :webhook_secret | :partner_link | :access_token
  @type parsed :: %{kind: kind(), environment: String.t() | nil, suite: boolean()}

  @suite_kinds %{
    "sk" => :secret,
    "psk" => :platform,
    "dsk" => :deploy,
    "whsec" => :webhook_secret,
    "pl" => :partner_link,
    "at" => :access_token
  }

  @doc """
  Classify a credential by its prefix. Returns `{:ok, %{kind:, environment:,
  suite:}}` (`environment` is `"live"`, `"test"` or `nil`; `suite` is true for
  the `atlas_<env>_<kind>_` format) or `:error` for anything else.
  """
  @spec parse(term()) :: {:ok, parsed()} | :error
  def parse("atlas_" <> rest) do
    case String.split(rest, "_", parts: 3) do
      [env, kind, _random] when env in ["live", "test"] ->
        case Map.fetch(@suite_kinds, kind) do
          {:ok, k} -> {:ok, %{kind: k, environment: env, suite: true}}
          :error -> :error
        end

      _ ->
        :error
    end
  end

  def parse(key) when is_binary(key) do
    case String.split(key, "_", parts: 3) do
      [kind, env, _rest] when kind in ["sk", "pk"] and env in ["live", "test"] ->
        {:ok, %{kind: if(kind == "sk", do: :secret, else: :publishable), environment: env, suite: false}}

      [kind, env, _rest] when kind in ["psk", "dsk", "whsec"] ->
        {:ok, %{kind: legacy_kind(kind), environment: if(env in ["live", "test"], do: env), suite: false}}

      [kind, _rest] when kind in ["psk", "dsk", "whsec"] ->
        {:ok, %{kind: legacy_kind(kind), environment: nil, suite: false}}

      _ ->
        :error
    end
  end

  def parse(_), do: :error

  defp legacy_kind("psk"), do: :platform
  defp legacy_kind("dsk"), do: :deploy
  defp legacy_kind("whsec"), do: :webhook_secret

  @doc "True for an instance secret key in either format (`atlas_live_sk_...` or `sk_live_...`)."
  @spec secret_key?(term()) :: boolean()
  def secret_key?(key), do: kind?(key, :secret)

  @doc "True for a platform key in either format (`atlas_live_psk_...` or `psk_...`)."
  @spec platform_key?(term()) :: boolean()
  def platform_key?(key), do: kind?(key, :platform)

  @doc "True for a publishable key (`pk_live_...` / `pk_test_...`); publishable keys have no suite form."
  @spec publishable_key?(term()) :: boolean()
  def publishable_key?(key), do: kind?(key, :publishable)

  @doc """
  True for a webhook signing secret in either format (`atlas_live_whsec_...` or
  `whsec_...`). Webhook verification is unchanged: the whole string is the HMAC key.
  """
  @spec webhook_secret?(term()) :: boolean()
  def webhook_secret?(key), do: kind?(key, :webhook_secret)

  @doc "True for a partner-link secret (`atlas_live_pl_...`)."
  @spec partner_link_secret?(term()) :: boolean()
  def partner_link_secret?(key), do: kind?(key, :partner_link)

  @doc "True for a one-hour access token from an operator token exchange (`atlas_live_at_...`)."
  @spec access_token?(term()) :: boolean()
  def access_token?(key), do: kind?(key, :access_token)

  defp kind?(key, kind), do: match?({:ok, %{kind: ^kind}}, parse(key))
end
