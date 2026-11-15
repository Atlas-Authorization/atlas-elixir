defmodule AtlasAuth.Http do
  @moduledoc false
  # A tiny zero-dependency HTTP call (:httpc) used by the OIDC relying party and the
  # doctor. Every caller takes an `:http` option so tests (and apps with their own
  # client) inject a function with the same shape:
  #
  #     (method, url, headers, body) -> {:ok, %{status: integer, headers: [{String.t, String.t}], body: binary}} | {:error, term}
  #
  # `headers` are lower-case `{name, value}` string pairs; `body` is `nil` or iodata.

  @type response :: %{status: non_neg_integer(), headers: [{String.t(), String.t()}], body: binary()}
  @type fun :: (atom(), String.t(), [{String.t(), String.t()}], iodata() | nil -> {:ok, response()} | {:error, term()})

  @spec request(atom(), String.t(), [{String.t(), String.t()}], iodata() | nil, keyword()) ::
          {:ok, response()} | {:error, term()}
  def request(method, url, headers, body, opts \\ []) do
    case Keyword.get(opts, :http) do
      fun when is_function(fun, 4) -> fun.(method, url, headers, body)
      _ -> httpc(method, url, headers, body, opts)
    end
  rescue
    e -> {:error, e}
  end

  defp httpc(method, url, headers, body, opts) do
    _ = :inets.start()
    _ = :ssl.start()
    hdrs = for {k, v} <- headers, do: {String.to_charlist(k), String.to_charlist(v)}
    timeout = Keyword.get(opts, :timeout_ms, 10_000)
    http_opts = [{:timeout, timeout}, {:connect_timeout, 5_000}, {:autoredirect, false}] ++ ssl_opts(url)

    request =
      case {method, body} do
        {m, nil} when m in [:get, :delete, :head] ->
          {String.to_charlist(url), hdrs}

        {_, b} ->
          type = Enum.find_value(headers, ~c"application/octet-stream", fn {k, v} -> if k == "content-type", do: String.to_charlist(v) end)
          {String.to_charlist(url), hdrs, type, IO.iodata_to_binary(b || "")}
      end

    case :httpc.request(method, request, http_opts, body_format: :binary) do
      {:ok, {{_v, status, _r}, rh, rb}} ->
        {:ok, %{status: status, headers: for({k, v} <- rh, do: {String.downcase(to_string(k)), to_string(v)}), body: rb}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp ssl_opts("https://" <> _) do
    [ssl: [verify: :verify_peer, cacerts: :public_key.cacerts_get(), depth: 3, customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]]]
  end

  defp ssl_opts(_), do: []

  @doc false
  def header(%{headers: headers}, name), do: Enum.find_value(headers, fn {k, v} -> if k == name, do: v end)

  @doc false
  def json(%{body: body}) do
    case Jason.decode(body) do
      {:ok, v} -> v
      _ -> nil
    end
  end
end
