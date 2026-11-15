defmodule AtlasAuth.DeviceFlow do
  @moduledoc """
  The OAuth 2.0 Device Authorization Grant (RFC 8628) against an instance's own OAuth server,
  for a CLI, TV or console of your own: `start/1` asks for a code, you show `user_code` and
  `verification_uri` (or `verification_uri_complete`), and `poll/2` waits for the person to approve.

      {:ok, flow} = AtlasAuth.DeviceFlow.start(issuer: "https://inst.atlas.example", client_id: "cli")
      IO.puts("Open \#{flow.verification_uri} and enter \#{flow.user_code}")
      {:ok, tokens} = AtlasAuth.DeviceFlow.poll(flow)

  To approve a code from your own app (the signed-in person's side), see `AtlasAuth.DeviceAuthorizations`.

  Options of `start/1`: `:issuer`, `:client_id` (required), `:client_secret` (a confidential client),
  `:scope` (string or list), `:resource`, `:http` (see `AtlasAuth.RP`). Options of `poll/2`: `:sleep`
  (`(ms -> any)`, default `Process.sleep/1`), `:now_ms`, `:http`.

  Errors are `{:error, %{error:, message:, status:}}` where `error` is the OAuth error
  (`"access_denied"`, `"expired_token"`, `"unauthorized_client"`, ...).
  """

  alias AtlasAuth.Http

  @grant "urn:ietf:params:oauth:grant-type:device_code"

  @spec start(keyword()) :: {:ok, map()} | {:error, map()}
  def start(opts) do
    base = opts |> Keyword.fetch!(:issuer) |> String.replace(~r/\/+\z/, "")
    scope = case opts[:scope] do
      l when is_list(l) -> Enum.join(l, " ")
      s -> s
    end

    form =
      [{"client_id", Keyword.fetch!(opts, :client_id)}] ++
        if(opts[:client_secret], do: [{"client_secret", opts[:client_secret]}], else: []) ++
        if(scope, do: [{"scope", scope}], else: []) ++
        if(opts[:resource], do: [{"resource", opts[:resource]}], else: [])

    case post(base <> "/oauth2/device_authorization", form, opts) do
      {:ok, 200, %{"device_code" => dc, "user_code" => uc} = body} ->
        {:ok,
         %{
           device_code: dc,
           user_code: uc,
           verification_uri: body["verification_uri"],
           verification_uri_complete: body["verification_uri_complete"],
           expires_in: body["expires_in"] || 600,
           interval: body["interval"] || 5,
           config: %{
             token_endpoint: base <> "/oauth2/token",
             client_id: opts[:client_id],
             client_secret: opts[:client_secret],
             http: opts[:http]
           }
         }}

      {:ok, status, body} ->
        {:error, failure(status, body, "Device authorization failed.")}

      {:error, reason} ->
        {:error, %{error: "request_failed", message: inspect(reason), status: 0}}
    end
  end

  @doc "Poll the token endpoint until the person approves, denies or the code expires. Honours `interval`, adds 5 s on each `slow_down`."
  @spec poll(map(), keyword()) :: {:ok, map()} | {:error, map()}
  def poll(%{config: config} = flow, opts \\ []) do
    sleep = opts[:sleep] || (&Process.sleep/1)
    now = opts[:now_ms] || fn -> System.system_time(:millisecond) end
    deadline = now.() + flow.expires_in * 1000
    do_poll(flow, config, sleep, now, deadline, max(1, flow.interval) * 1000, Keyword.merge([http: config[:http]], opts))
  end

  defp do_poll(flow, config, sleep, now, deadline, interval, opts) do
    if now.() >= deadline do
      {:error, %{error: "expired_token", message: "The sign-in code expired. Run the login again.", status: 400}}
    else
      sleep.(interval)

      form =
        [{"grant_type", @grant}, {"device_code", flow.device_code}, {"client_id", config.client_id}] ++
          if(config.client_secret, do: [{"client_secret", config.client_secret}], else: [])

      case post(config.token_endpoint, form, opts) do
        {:ok, 200, tokens} -> {:ok, tokens}
        {:ok, _, %{"error" => "authorization_pending"}} -> do_poll(flow, config, sleep, now, deadline, interval, opts)
        {:ok, _, %{"error" => "slow_down"}} -> do_poll(flow, config, sleep, now, deadline, interval + 5000, opts)
        {:ok, status, body} -> {:error, failure(status, body, "Sign-in failed.")}
        {:error, reason} -> {:error, %{error: "request_failed", message: inspect(reason), status: 0}}
      end
    end
  end

  defp post(url, form, opts) do
    headers = [{"content-type", "application/x-www-form-urlencoded"}, {"accept", "application/json"}]

    with {:ok, res} <- Http.request(:post, url, headers, URI.encode_query(form), Keyword.take(opts, [:http])) do
      {:ok, res.status, Http.json(res) || %{}}
    end
  end

  defp failure(status, body, default),
    do: %{error: to_string(body["error"] || "error"), message: to_string(body["error_description"] || default), status: status}
end
