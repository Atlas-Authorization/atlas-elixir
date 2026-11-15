defmodule Atlas.Doctor do
  @moduledoc """
  Checks that your Atlas setup works, with one call. Run it from a release task, a health endpoint or `iex`:

      client = Atlas.new(System.fetch_env!("ATLAS_SECRET_KEY"))
      report = Atlas.Doctor.run(client, issuer: "https://inst.atlas.example")
      report.ok?                          # false when any check failed
      Atlas.Doctor.format(report) |> IO.puts()

  The checks (each is `%{name:, status: :pass | :warn | :fail, message:}`):

    * `:key` - the secret key looks like a secret key (not a publishable key) and names its mode.
    * `:config` - the API base URL is https (http only for localhost); the issuer, when given, is https.
    * `:api` - the public status endpoint answers and the service is operational (degraded or down is a warning).
    * `:clock` - your clock against the API's `Date` header: warns above 5s, fails above 60s of skew (tokens are
      checked with a small leeway, so a wrong clock rejects good tokens).
    * `:instance` - an authenticated read of your instance succeeds with this key (a 401 means a wrong or revoked key,
      a 403 a key without the scope).
    * `:jwks` - the instance JWKS is reachable and carries at least one key (needs `:jwks_url` or `:issuer`).

  Options: `:issuer`, `:jwks_url` (default `<issuer>/.well-known/jwks.json`), `:fetcher` (the JWKS fetcher of
  `AtlasAuth.Verifier`), `:now_ms`. Nothing is sent that a normal call would not send; no secret is ever put in the report.
  """

  @warn_skew_s 5
  @fail_skew_s 60

  @type check :: %{name: atom(), status: :pass | :warn | :fail, message: String.t()}
  @type report :: %{ok?: boolean(), checks: [check()]}

  @spec run(Atlas.Client.t(), keyword()) :: report()
  def run(%Atlas.Client{} = client, opts \\ []) do
    {api, clock} = api_and_clock(client, opts)

    checks =
      [key_check(client), config_check(client, opts), api] ++ [clock, instance_check(client), jwks_check(opts)]

    for c <- checks, do: AtlasAuth.Telemetry.execute([:atlas, :doctor, :check], %{}, %{name: c.name, status: c.status})
    %{ok?: Enum.all?(checks, &(&1.status != :fail)), checks: checks}
  end

  @doc "The report as text, one line per check."
  @spec format(report()) :: String.t()
  def format(%{checks: checks, ok?: ok?}) do
    lines = for c <- checks, do: "#{icon(c.status)} #{String.pad_trailing(to_string(c.name), 9)} #{c.message}"
    Enum.join(lines ++ [if(ok?, do: "All checks passed.", else: "Some checks failed.")], "\n")
  end

  defp icon(:pass), do: "[ok]  "
  defp icon(:warn), do: "[warn]"
  defp icon(:fail), do: "[FAIL]"

  defp key_check(%{secret_key: "pk_" <> _}), do: check(:key, :fail, "this is a publishable key (pk_...); the Backend API needs a secret key (sk_...)")

  defp key_check(%{secret_key: "sk_" <> rest}) do
    mode = cond do
      String.starts_with?(rest, "live") -> "live"
      String.starts_with?(rest, "test") -> "test"
      true -> "unknown mode"
    end

    check(:key, :pass, "secret key (#{mode})")
  end

  defp key_check(_), do: check(:key, :warn, "the key does not start with sk_: check it is an Atlas secret key")

  defp config_check(client, opts) do
    problems =
      [
        if(not secure?(client.base_url), do: "base URL #{client.base_url} is not https"),
        if(opts[:issuer] && not secure?(opts[:issuer]), do: "issuer #{opts[:issuer]} is not https")
      ]
      |> Enum.reject(&is_nil/1)

    if problems == [], do: check(:config, :pass, "base URL #{client.base_url}"), else: check(:config, :fail, Enum.join(problems, "; "))
  end

  defp secure?(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} -> true
      %URI{scheme: "http", host: h} when h in ["localhost", "127.0.0.1", "::1"] -> true
      _ -> false
    end
  end

  defp api_and_clock(client, opts) do
    now_ms = opts[:now_ms] || System.system_time(:millisecond)

    case Atlas.Client.raw(client, :get, "/v1/status") do
      {:ok, %Req.Response{status: s} = r} when s in 200..299 ->
        status =
          case Jason.decode(r.body || "") do
            {:ok, %{"status" => v} = b} ->
              backend = Enum.find(b["components"] || [], &(&1["id"] == "backend_api"))
              if backend && backend["status"] == "major_outage", do: "major_outage", else: v

            _ ->
              "unknown"
          end

        api =
          case status do
            "operational" -> check(:api, :pass, "the API is operational")
            "unknown" -> check(:api, :warn, "the status endpoint answered without a status")
            other -> check(:api, :warn, "the service reports #{other}; calls may be slow or fail, retries are on")
          end

        {api, clock_check(r, now_ms)}

      {:ok, %Req.Response{status: s}} ->
        {check(:api, :fail, "the status endpoint answered HTTP #{s}"), check(:clock, :warn, "not checked: no status answer")}

      {:error, e} ->
        {check(:api, :fail, "the API is unreachable: #{e.message}"), check(:clock, :warn, "not checked: the API is unreachable")}
    end
  end

  defp clock_check(%Req.Response{} = resp, now_ms) do
    date = resp |> Req.Response.get_header("date") |> List.first()

    case date && :httpd_util.convert_request_date(String.to_charlist(date)) do
      {{_, _, _}, {_, _, _}} = dt ->
        server = (:calendar.datetime_to_gregorian_seconds(dt) - 62_167_219_200)
        skew = abs(div(now_ms, 1000) - server)

        cond do
          skew > @fail_skew_s -> check(:clock, :fail, "your clock is #{skew}s away from the API's: fix NTP, tokens will be rejected")
          skew > @warn_skew_s -> check(:clock, :warn, "your clock is #{skew}s away from the API's")
          true -> check(:clock, :pass, "clock skew #{skew}s")
        end

      _ ->
        check(:clock, :warn, "the API sent no readable Date header")
    end
  end

  defp instance_check(client) do
    case Atlas.Client.raw(client, :get, "/v1/instance") do
      {:ok, %Req.Response{status: s}} when s in 200..299 -> check(:instance, :pass, "the key can read the instance")
      {:ok, %Req.Response{status: 401}} -> check(:instance, :fail, "the API rejected the key (401): wrong, revoked or from another instance")
      {:ok, %Req.Response{status: 403}} -> check(:instance, :fail, "the key lacks the instance:read scope (403)")
      {:ok, %Req.Response{status: s}} -> check(:instance, :fail, "the instance read answered HTTP #{s}")
      {:error, e} -> check(:instance, :fail, "the instance read failed: #{e.message}")
    end
  end

  defp jwks_check(opts) do
    url = opts[:jwks_url] || (opts[:issuer] && String.trim_trailing(opts[:issuer], "/") <> "/.well-known/jwks.json")
    fetcher = opts[:fetcher] || (&AtlasAuth.Verifier.default_fetch/1)

    cond do
      url == nil -> check(:jwks, :warn, "not checked: pass :issuer or :jwks_url")
      true ->
        case fetcher.(url) do
          {:ok, [_ | _] = keys} -> check(:jwks, :pass, "#{length(keys)} signing key(s) at #{url}")
          {:ok, _} -> check(:jwks, :fail, "the JWKS at #{url} has no keys")
          {:error, reason} -> check(:jwks, :fail, "the JWKS at #{url} is unreachable: #{inspect(reason)}")
        end
    end
  end

  defp check(name, status, message), do: %{name: name, status: status, message: message}
end
