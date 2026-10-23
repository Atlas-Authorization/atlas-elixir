defmodule AtlasAuth.DeviceAuthorizations do
  @moduledoc """
  Device sign-in approval (OAuth 2.0 Device Authorization Grant, RFC 8628) from
  your own app: the signed-in user types — or scans — the code a TV, console or
  CLI shows, and your app approves it instead of sending them to Atlas's hosted
  `/oauth2/device` page.

  These calls run on the Frontend API as the signed-in USER: they need the
  user's session token (a native app's session JWT), never a secret key.

      opts = [frontend_api: "https://clerk.example.com", session_token: jwt]
      {:ok, auth} = AtlasAuth.DeviceAuthorizations.lookup(typed_code, opts)
      {:ok, _} = AtlasAuth.DeviceAuthorizations.approve(auth, opts)

  Options: `:frontend_api` and `:session_token` (required),
  `:publishable_key` (sent as `x-publishable-key`), `:poster` —
  `(url, headers, body -> {:ok, status, body} | {:error, term})`, default
  `:httpc`. A refusal is `{:error, %{status:, code:, message:}}`; `code`
  `"STEP_UP_REQUIRED"` means approving needs a fresh re-authentication.
  """

  @base "/v1/client/me/device_authorizations"

  @doc "Normalise what a person typed into the `XXXX-XXXX` form devices show."
  @spec format_user_code(String.t()) :: String.t()
  def format_user_code(input) do
    cleaned = input |> String.upcase() |> String.replace(~r/[^A-Z0-9]/, "")

    if String.length(cleaned) == 8,
      do: String.slice(cleaned, 0, 4) <> "-" <> String.slice(cleaned, 4, 4),
      else: String.trim(input)
  end

  @doc "The `user_code` of a verification URL a device displayed, formatted; nil when none."
  @spec user_code_from_url(String.t()) :: String.t() | nil
  def user_code_from_url(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, query: query} when is_binary(scheme) and is_binary(query) ->
        case URI.decode_query(query)["user_code"] do
          value when is_binary(value) and value != "" -> format_user_code(value)
          _ -> nil
        end

      _ ->
        nil
    end
  end

  @doc "Find a pending device sign-in by the code the device shows."
  def lookup(user_code, opts), do: call(@base <> "/lookup", format_user_code(user_code), opts)

  @doc "Approve for the signed-in user; the device's next poll receives its tokens."
  def approve(%{"id" => id, "user_code" => code}, opts),
    do: call(@base <> "/" <> URI.encode_www_form(id) <> "/approve", code, opts)

  @doc "Deny; the device's next poll is told `access_denied`."
  def deny(%{"id" => id, "user_code" => code}, opts),
    do: call(@base <> "/" <> URI.encode_www_form(id) <> "/deny", code, opts)

  defp call(path, user_code, opts) do
    base = opts |> Keyword.fetch!(:frontend_api) |> String.trim_trailing("/")
    token = Keyword.fetch!(opts, :session_token)

    headers =
      [
        {"authorization", "Bearer " <> token},
        {"accept", "application/json"},
        {"content-type", "application/json"}
      ] ++ if(opts[:publishable_key], do: [{"x-publishable-key", opts[:publishable_key]}], else: [])

    poster = Keyword.get(opts, :poster, &AtlasAuth.Introspection.default_post/3)

    case poster.(base <> path, headers, Jason.encode!(%{user_code: user_code})) do
      {:ok, status, raw} when status in 200..299 ->
        case Jason.decode(raw) do
          {:ok, map} when is_map(map) -> {:ok, map}
          _ -> {:ok, %{}}
        end

      {:ok, status, raw} ->
        first =
          case Jason.decode(raw) do
            {:ok, %{"errors" => [first | _]}} when is_map(first) -> first
            _ -> %{}
          end

        {:error, %{status: status, code: first["code"] || "UNKNOWN", message: first["message"] || "The request failed."}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
