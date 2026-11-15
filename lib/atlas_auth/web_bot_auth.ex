defmodule AtlasAuth.WebBotAuth do
  @moduledoc """
  Web Bot Auth: verify who is behind an automated request.

  A bot signs its requests with an Ed25519 key (RFC 9421 HTTP Message Signatures, tag
  `web-bot-auth`) and names the place its public keys live in the `Signature-Agent` header. The
  key is found in the directory served at
  `<Signature-Agent>/.well-known/http-message-signatures-directory`, and the signature's `keyid`
  is the RFC 7638 JWK thumbprint of that key.

      result =
        AtlasAuth.WebBotAuth.verify(
          %{method: conn.method, url: request_url, headers: conn.req_headers},
          get_keys: AtlasAuth.WebBotAuth.DirectoryCache.getter(cache)
        )

      if result.verified, do: allow(result.directory), else: treat_as_unverified(result.reason)

  `verify/2` never raises on bad input. Fetching the directory is injected (`:get_keys`, a function
  `(directory_url, refresh? -> [jwk] | nil)`), so you bring your own network policy; use
  `AtlasAuth.WebBotAuth.DirectoryCache` for a cached one. Options: `:get_keys` (required), `:now_ms`,
  `:skew_seconds` (30), `:max_lifetime_seconds` (3600), `:claim_nonce` (a function
  `(key, expires_at_ms -> boolean)` that returns true the first time a nonce is seen; without it
  nonces are not tracked).

  The request map is `%{method:, url:, headers:}`, `url` the absolute URL as the origin server saw
  it and `headers` a list of `{name, value}` pairs or a map.

  Limits of this port: covered header components with the `sf` parameter are refused
  (`:unsupported_component`), and the `key` parameter reads the dictionary member as sent without
  re-canonicalising it; both fail closed. `@target-uri` and `@path` are taken from the URL as given.
  """

  @tag "web-bot-auth"
  @directory_path "/.well-known/http-message-signatures-directory"
  @derived ~w(@method @authority @path @target-uri @scheme @query @request-target)

  @type failure ::
          :no_signature | :no_web_bot_auth_signature | :malformed | :missing_signature_agent | :bad_signature_agent
          | :bad_params | :unsupported_algorithm | :unsupported_component | :component_missing | :components_not_covered
          | :bad_request | :not_yet_valid | :expired | :lifetime_too_long | :directory_unavailable | :key_not_found
          | :bad_signature | :replayed

  @doc "The media type a directory is served as."
  def directory_media_type, do: "application/http-message-signatures-directory+json"

  @doc "The URL a directory is fetched from."
  @spec directory_url_for(String.t()) :: String.t()
  def directory_url_for(directory), do: directory <> @directory_path

  # --- keys -----------------------------------------------------------------

  @doc "RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public JWK: the web-bot-auth `keyid`."
  @spec jwk_thumbprint(map()) :: String.t()
  def jwk_thumbprint(%{"x" => x}), do: b64url(:crypto.hash(:sha256, ~s({"crv":"Ed25519","kty":"OKP","x":"#{x}"})))

  @doc "The raw 32-byte public key of a JWK, or nil when it is not a well-formed Ed25519 key."
  @spec jwk_bytes(term()) :: binary() | nil
  def jwk_bytes(%{"kty" => "OKP", "crv" => "Ed25519", "x" => x}) when is_binary(x) do
    case Base.url_decode64(x, padding: false) do
      {:ok, <<_::binary-size(32)>> = bytes} -> bytes
      _ -> nil
    end
  end

  def jwk_bytes(_), do: nil

  @doc "The usable Ed25519 keys of a directory document (a JWK Set). At most 20 are kept."
  @spec parse_directory(term()) :: [map()]
  def parse_directory(%{"keys" => keys}) when is_list(keys), do: keys |> Enum.filter(&(jwk_bytes(&1) != nil)) |> Enum.take(20)
  def parse_directory(_), do: []

  @doc """
  Canonical form of a directory reference: `https://host[:port][/path]`. A bare host gets `https://`.
  Nil for anything that is not an https URL without credentials, query or fragment.
  """
  @spec normalize_directory(String.t()) :: String.t() | nil
  def normalize_directory(input) do
    s = String.trim(input)
    s = if Regex.match?(~r/^[a-z][a-z0-9+.-]*:\/\//i, s), do: s, else: "https://" <> s

    case URI.parse(s) do
      %URI{scheme: scheme, host: host, userinfo: nil, query: nil, fragment: nil, port: port, path: path}
      when is_binary(host) and host != "" ->
        if String.downcase(scheme || "") == "https" do
          port_part = if port in [nil, 443], do: "", else: ":#{port}"
          "https://" <> String.downcase(host) <> port_part <> String.replace(path || "", ~r/\/+$/, "")
        end

      _ ->
        nil
    end
  end

  # --- structured fields ----------------------------------------------------

  # Split on `sep` outside strings and parentheses; members trimmed, empty ones dropped.
  defp split_top(s, sep), do: do_split(s, sep, 0, false, "", [])

  defp do_split(<<>>, _sep, _d, _q, cur, acc), do: Enum.reverse(push(cur, acc))
  defp do_split(<<?\\, c, rest::binary>>, sep, d, true, cur, acc), do: do_split(rest, sep, d, true, cur <> <<?\\, c>>, acc)
  defp do_split(<<?", rest::binary>>, sep, d, q, cur, acc), do: do_split(rest, sep, d, not q, cur <> "\"", acc)
  defp do_split(<<c, rest::binary>>, sep, d, true, cur, acc), do: do_split(rest, sep, d, true, cur <> <<c>>, acc)
  defp do_split(<<?(, rest::binary>>, sep, d, q, cur, acc), do: do_split(rest, sep, d + 1, q, cur <> "(", acc)
  defp do_split(<<?), rest::binary>>, sep, d, q, cur, acc), do: do_split(rest, sep, d - 1, q, cur <> ")", acc)
  defp do_split(<<c, rest::binary>>, <<c>> = sep, 0, q, cur, acc), do: do_split(rest, sep, 0, q, "", push(cur, acc))
  defp do_split(<<c, rest::binary>>, sep, d, q, cur, acc), do: do_split(rest, sep, d, q, cur <> <<c>>, acc)

  defp push(cur, acc), do: if(String.trim(cur) == "", do: acc, else: [String.trim(cur) | acc])

  # Read a quoted sf-string at the start of `s`. {:ok, value, rest} | :error.
  defp read_string(<<?", rest::binary>>), do: read_string(rest, "")
  defp read_string(_), do: :error

  defp read_string(<<?\\, c, rest::binary>>, acc) when c in [?", ?\\], do: read_string(rest, acc <> <<c>>)
  defp read_string(<<?\\, _::binary>>, _acc), do: :error
  defp read_string(<<?", rest::binary>>, acc), do: {:ok, acc, rest}
  defp read_string(<<c, rest::binary>>, acc) when c >= 0x20 and c <= 0x7E, do: read_string(rest, acc <> <<c>>)
  defp read_string(_, _acc), do: :error

  defp key_char?(c), do: c in ?a..?z or c in ?0..?9 or c in [?_, ?., ?*, ?-]
  defp token_char?(c), do: c in ?A..?Z or c in ?a..?z or c in ?0..?9 or c in ~c(:/!#$%&'*+-.^_`|~)

  defp take_while(bin, fun), do: take_while(bin, fun, "")
  defp take_while(<<c, rest::binary>> = bin, fun, acc), do: if(fun.(c), do: take_while(rest, fun, acc <> <<c>>), else: {acc, bin})
  defp take_while(<<>>, _fun, acc), do: {acc, ""}

  defp valid_key?(<<c, _::binary>> = k), do: (c in ?a..?z or c == ?*) and String.match?(k, ~r/^[a-z*][a-z0-9_.*-]*$/)
  defp valid_key?(_), do: false

  # `;k=v;k2` -> {:ok, [{key, value}]} (in order) | :error. Values: string, integer, float, boolean, {:bytes, bin}.
  defp parse_params(text), do: parse_params(text, [])

  defp parse_params("", acc), do: {:ok, Enum.reverse(acc)}

  defp parse_params(<<";", rest::binary>>, acc) do
    {key, rest} = take_while(rest, &key_char?/1)

    cond do
      not valid_key?(key) -> :error
      match?(<<"=", _::binary>>, rest) ->
        <<"=", v::binary>> = rest

        case parse_value(v) do
          {:ok, value, rest} -> parse_params(rest, [{key, value} | acc])
          :error -> :error
        end

      true ->
        parse_params(rest, [{key, true} | acc])
    end
  end

  defp parse_params(_, _), do: :error

  defp parse_value(<<?", _::binary>> = v), do: read_string(v)

  defp parse_value(<<?:, rest::binary>>) do
    with [b64, after_colon] <- :binary.split(rest, ":"),
         {:ok, bytes} <- decode64(b64) do
      {:ok, {:bytes, bytes}, after_colon}
    else
      _ -> :error
    end
  end

  defp parse_value(<<??, b, rest::binary>>) when b in [?0, ?1], do: {:ok, b == ?1, rest}

  defp parse_value(<<c, _::binary>> = v) when c == ?- or c in ?0..?9 do
    {n, rest} = take_while(v, fn ch -> ch in ?0..?9 or ch in [?-, ?.] end)

    cond do
      Regex.match?(~r/^-?\d{1,15}$/, n) -> {:ok, String.to_integer(n), rest}
      Regex.match?(~r/^-?\d{1,15}\.\d{1,3}$/, n) -> {:ok, String.to_float(n), rest}
      true -> :error
    end
  end

  defp parse_value(<<c, _::binary>> = v) when c in ?A..?Z or c in ?a..?z or c == ?* do
    {t, rest} = take_while(v, &token_char?/1)
    {:ok, t, rest}
  end

  defp parse_value(_), do: :error

  defp decode64(s) do
    case Base.decode64(s) do
      {:ok, b} -> {:ok, b}
      :error -> Base.decode64(s, padding: false)
    end
  end

  @doc """
  Parse a `Signature-Input` field into `[%{label:, components: [{name, params}], params: [{key, value}], raw:}]`
  (`raw` is the inner list with its parameters exactly as sent: the `@signature-params` value), or `:error`.
  """
  @spec parse_signature_input(String.t()) :: {:ok, [map()]} | :error
  def parse_signature_input(header) do
    members = split_top(header, ",")

    results =
      Enum.map(members, fn member ->
        with [label, raw] <- String.split(member, "=", parts: 2),
             label = String.trim(label),
             raw = String.trim(raw),
             true <- valid_key?(label) and String.starts_with?(raw, "("),
             {:ok, inner, rest} <- split_inner(raw),
             {:ok, components} <- parse_components(inner, []),
             {:ok, params} <- parse_params(rest) do
          {:ok, %{label: label, components: components, params: params, raw: raw}}
        else
          _ -> :error
        end
      end)

    if members != [] and Enum.all?(results, &match?({:ok, _}, &1)),
      do: {:ok, Enum.map(results, fn {:ok, r} -> r end)},
      else: :error
  end

  # "(a b);p=1" -> {:ok, "a b", ";p=1"}, ignoring ")" inside quotes.
  defp split_inner(<<"(", rest::binary>>), do: split_inner(rest, "", false)

  defp split_inner(<<?\\, c, rest::binary>>, acc, true), do: split_inner(rest, acc <> <<?\\, c>>, true)
  defp split_inner(<<?", rest::binary>>, acc, q), do: split_inner(rest, acc <> "\"", not q)
  defp split_inner(<<?), rest::binary>>, acc, false), do: {:ok, acc, rest}
  defp split_inner(<<c, rest::binary>>, acc, q), do: split_inner(rest, acc <> <<c>>, q)
  defp split_inner(<<>>, _acc, _q), do: :error

  defp parse_components("", acc), do: {:ok, Enum.reverse(acc)}
  defp parse_components(<<" ", rest::binary>>, acc), do: parse_components(rest, acc)

  defp parse_components(inner, acc) do
    with {:ok, name, rest} <- read_string(inner),
         {ptext, rest} = component_params(rest, "", false),
         {:ok, params} <- parse_params(ptext) do
      parse_components(rest, [{name, params} | acc])
    else
      _ -> :error
    end
  end

  defp component_params(<<" ", _::binary>> = rest, acc, false), do: {acc, rest}
  defp component_params(<<?\\, c, rest::binary>>, acc, true), do: component_params(rest, acc <> <<?\\, c>>, true)
  defp component_params(<<?", rest::binary>>, acc, q), do: component_params(rest, acc <> "\"", not q)
  defp component_params(<<c, rest::binary>>, acc, q), do: component_params(rest, acc <> <<c>>, q)
  defp component_params(<<>>, acc, _q), do: {acc, ""}

  @doc "Parse a `Signature` field into `%{label => signature_bytes}`, or `:error`."
  @spec parse_signature_header(String.t()) :: {:ok, %{String.t() => binary()}} | :error
  def parse_signature_header(header) do
    members = split_top(header, ",")

    parsed =
      Enum.map(members, fn m ->
        with [_, label, b64] <- Regex.run(~r/^([a-z*][a-z0-9_.*-]*)=:([A-Za-z0-9+\/=]*):$/, m),
             {:ok, bytes} <- decode64(b64) do
          {label, bytes}
        else
          _ -> :error
        end
      end)

    if members != [] and :error not in parsed, do: {:ok, Map.new(parsed)}, else: :error
  end

  @doc """
  The directory a `Signature-Agent` value names, normalised. Accepts a quoted string, a bare URL,
  or the dictionary form (`sig1="https://bot.example"`; the member for `label` wins, else the first).
  """
  @spec parse_signature_agent(String.t(), String.t() | nil) :: String.t() | nil
  def parse_signature_agent(value, label \\ nil) do
    v = String.trim(value)

    v =
      if Regex.match?(~r/^[a-z*][a-z0-9_.*-]*=/, v) do
        members = split_top(v, ",")
        pick = Enum.find(members, hd(members), &(label != nil and String.starts_with?(&1, label <> "=")))
        pick |> String.split("=", parts: 2) |> List.last() |> String.trim()
      else
        v
      end

    cond do
      v == "" -> nil
      String.starts_with?(v, "\"") ->
        case read_string(v) do
          {:ok, str, ""} -> normalize_directory(str)
          _ -> nil
        end

      true ->
        normalize_directory(v)
    end
  end

  # --- signature base (RFC 9421 section 2.5) --------------------------------

  @doc "A header's value as RFC 9421 reads it: fields of one name joined with \", \", trimmed. Nil when absent."
  @spec header_value(list() | map(), String.t()) :: String.t() | nil
  def header_value(headers, name) do
    lower = String.downcase(name)

    values =
      for {k, v} <- Enum.to_list(headers), String.downcase(to_string(k)) == lower, item <- List.wrap(v), do: String.trim(to_string(item))

    if values == [], do: nil, else: Enum.join(values, ", ")
  end

  @doc "The component identifier as written in `Signature-Input` and the signature base: `\"name\";param=value`."
  @spec serialize_component_id(String.t() | {String.t(), list()}) :: String.t()
  def serialize_component_id(name) when is_binary(name), do: serialize_component_id({name, []})

  def serialize_component_id({name, params}) do
    Enum.reduce(params, sf_string(name), fn
      {k, true}, acc -> acc <> ";" <> k
      {k, false}, acc -> acc <> ";" <> k <> "=?0"
      {k, v}, acc when is_binary(v) -> acc <> ";" <> k <> "=" <> sf_string(v)
      {k, v}, acc when is_number(v) -> acc <> ";" <> k <> "=" <> to_string(v)
      {k, {:bytes, b}}, acc -> acc <> ";" <> k <> "=:" <> Base.encode64(b) <> ":"
    end)
  end

  defp sf_string(v), do: "\"" <> String.replace(v, ~r/[\\"]/, "\\\\\\0") <> "\""

  @doc """
  Build the signature base: one `"id": value` line per covered component, then the `@signature-params`
  line. A component is a name or `{name, params}`. Returns `{:ok, base}` or
  `{:error, :unsupported_component | :component_missing | :bad_request}`.
  """
  @spec build_signature_base(map(), [String.t() | {String.t(), list()}], String.t()) :: {:ok, String.t()} | {:error, atom()}
  def build_signature_base(req, components, signature_params) do
    case URI.parse(req.url) do
      %URI{scheme: scheme, host: host} = url when is_binary(scheme) and is_binary(host) and host != "" ->
        lines =
          Enum.reduce_while(components, {MapSet.new(), []}, fn entry, {seen, acc} ->
            c = if is_binary(entry), do: {entry, []}, else: entry
            id = serialize_component_id(c)

            with :ok <- check_component(c, seen, id),
                 {:ok, v} <- component_value(c, req, url) do
              {:cont, {MapSet.put(seen, id), [id <> ": " <> v | acc]}}
            else
              {:error, e} -> {:halt, {:error, e}}
            end
          end)

        case lines do
          {:error, e} -> {:error, e}
          {_, acc} -> {:ok, Enum.join(Enum.reverse(["\"@signature-params\": " <> signature_params | acc]), "\n")}
        end

      _ ->
        {:error, :bad_request}
    end
  end

  defp check_component({name, params}, seen, id) do
    keys = Enum.map(params, &elem(&1, 0))

    cond do
      name != String.downcase(name) -> {:error, :unsupported_component}
      String.starts_with?(name, "@") and name not in @derived and name != "@query-param" -> {:error, :unsupported_component}
      MapSet.member?(seen, id) -> {:error, :unsupported_component}
      not Enum.all?(keys, &(&1 in ["sf", "key", "bs", "name"])) -> {:error, :unsupported_component}
      String.starts_with?(name, "@") and name != "@query-param" and keys != [] -> {:error, :unsupported_component}
      true -> :ok
    end
  end

  defp component_value({"@query-param", params}, _req, url) do
    case params do
      [{"name", n}] when is_binary(n) ->
        found = for {k, v} <- URI.query_decoder(url.query || "") |> Enum.to_list(), k == n, do: v
        if match?([_], found), do: {:ok, URI.encode(hd(found), &URI.char_unreserved?/1)}, else: {:error, :component_missing}

      _ ->
        {:error, :component_missing}
    end
  end

  defp component_value({"@" <> _ = name, params}, req, url) do
    path = if url.path in [nil, ""], do: "/", else: url.path
    search = if url.query in [nil, ""], do: "", else: "?" <> url.query

    value =
      if params != [] do
        nil
      else
        case name do
          "@method" -> String.upcase(req.method)
          "@authority" -> authority(url)
          "@path" -> path
          "@target-uri" -> req.url
          "@scheme" -> String.downcase(url.scheme)
          "@query" -> if search == "", do: "?", else: search
          "@request-target" -> path <> search
        end
      end

    if value && not String.contains?(value, ["\r", "\n"]), do: {:ok, value}, else: {:error, :component_missing}
  end

  defp component_value({name, params}, req, _url) do
    raw = header_value(req.headers, name)

    value =
      cond do
        raw == nil -> nil
        params == [] -> raw
        match?([{"bs", true}], params) -> ":" <> Base.encode64(raw) <> ":"
        match?([{"key", k}] when is_binary(k), params) -> dictionary_member(raw, elem(hd(params), 1))
        # `sf` (and anything else) is not supported: fail closed.
        true -> :unsupported
      end

    case value do
      :unsupported -> {:error, :unsupported_component}
      v when is_binary(v) -> if String.contains?(v, ["\r", "\n"]), do: {:error, :component_missing}, else: {:ok, v}
      _ -> {:error, :component_missing}
    end
  end

  defp dictionary_member(raw, key) do
    Enum.find_value(split_top(raw, ","), fn m ->
      cond do
        String.starts_with?(m, key <> "=") -> m |> String.split("=", parts: 2) |> List.last() |> String.trim()
        m == key -> "?1"
        true -> nil
      end
    end)
  end

  defp authority(%URI{host: host, port: port, scheme: scheme}) do
    default = if String.downcase(scheme) == "https", do: 443, else: 80
    h = String.downcase(host)
    h = if String.contains?(h, ":"), do: "[" <> h <> "]", else: h
    if port in [nil, default], do: h, else: "#{h}:#{port}"
  end

  # --- verification ---------------------------------------------------------

  @doc "Verify the web-bot-auth signature on a request. See the module doc. Returns a result map (never raises on bad input)."
  @spec verify(map(), keyword()) :: map()
  def verify(req, opts) do
    input_header = header_value(req.headers, "signature-input")
    sig_header = header_value(req.headers, "signature")

    if input_header == nil or sig_header == nil do
      %{signed: false, verified: false, reason: :no_signature}
    else
      with {:ok, inputs} <- parse_signature_input(input_header),
           {:ok, sigs} <- parse_signature_header(sig_header) do
        pick =
          Enum.find(inputs, fn i -> List.keyfind(i.params, "tag", 0) == {"tag", @tag} and Map.has_key?(sigs, i.label) end)

        if pick, do: verify_input(req, opts, pick, Map.fetch!(sigs, pick.label)), else: fail(:no_web_bot_auth_signature)
      else
        _ -> fail(:malformed)
      end
    end
  end

  defp fail(reason, extra \\ %{}), do: Map.merge(%{signed: true, verified: false, reason: reason}, extra)

  defp verify_input(req, opts, input, signature) do
    p = Map.new(input.params)
    created = p["created"]
    expires = p["expires"]
    key_id = p["keyid"]
    nonce = p["nonce"]

    if not (is_integer(created) and is_integer(expires) and is_binary(key_id) and key_id != "" and byte_size(key_id) <= 128) or
         (nonce != nil and not (is_binary(nonce) and byte_size(nonce) <= 512)) do
      fail(:bad_params, %{label: input.label})
    else
      base = %{label: input.label, key_id: key_id, created: created, expires: expires}
      now_sec = div(Keyword.get(opts, :now_ms, System.system_time(:millisecond)), 1000)
      skew = Keyword.get(opts, :skew_seconds, 30)
      max_life = Keyword.get(opts, :max_lifetime_seconds, 3600)

      cond do
        p["alg"] != nil and p["alg"] != "ed25519" -> fail(:unsupported_algorithm, base)
        expires <= created -> fail(:bad_params, base)
        expires - created > max_life -> fail(:lifetime_too_long, base)
        created > now_sec + skew -> fail(:not_yet_valid, base)
        expires < now_sec - skew -> fail(:expired, base)
        true -> verify_covered(req, opts, input, signature, base, nonce, skew)
      end
    end
  end

  defp verify_covered(req, opts, input, signature, base, nonce, skew) do
    names = Enum.map(input.components, &elem(&1, 0))
    agent_header = header_value(req.headers, "signature-agent")
    agent_component = Enum.find(input.components, fn {n, _} -> n == "signature-agent" end)

    cond do
      agent_header == nil ->
        fail(:missing_signature_agent, base)

      "@authority" not in names or agent_component == nil ->
        fail(:components_not_covered, base)

      true ->
        {_, agent_params} = agent_component
        agent_key = case List.keyfind(agent_params, "key", 0) do
          {"key", k} when is_binary(k) -> k
          _ -> nil
        end

        # Covered as a dictionary member: the directory must come from that member, or an uncovered one could be swapped in.
        if agent_key != nil and not Enum.any?(split_top(agent_header, ","), &String.starts_with?(&1, agent_key <> "=")) do
          fail(:bad_signature_agent, base)
        else
          case parse_signature_agent(agent_header, agent_key || input.label) do
            nil -> fail(:bad_signature_agent, base)
            directory -> verify_signature(req, opts, input, signature, Map.put(base, :directory, directory), nonce, skew)
          end
        end
    end
  end

  defp verify_signature(req, opts, input, signature, with_dir, nonce, skew) do
    case build_signature_base(req, input.components, input.raw) do
      {:error, e} ->
        fail(e, with_dir)

      {:ok, sig_base} ->
        dir_url = directory_url_for(with_dir.directory)
        get_keys = Keyword.fetch!(opts, :get_keys)
        find = fn keys -> keys && Enum.find(keys, &(jwk_thumbprint(&1) == with_dir.key_id)) end
        keys = get_keys.(dir_url, false)
        {jwk, keys} = case find.(keys) do
          nil -> (fn k -> {find.(k), k} end).(get_keys.(dir_url, true))
          j -> {j, keys}
        end

        cond do
          jwk == nil -> fail(if(keys == nil, do: :directory_unavailable, else: :key_not_found), with_dir)
          not valid_signature?(jwk, sig_base, signature) -> fail(:bad_signature, with_dir)
          true -> claim_nonce(opts, with_dir, nonce, skew)
        end
    end
  end

  defp valid_signature?(jwk, sig_base, signature) do
    pub = jwk_bytes(jwk)
    pub != nil and byte_size(signature) == 64 and :crypto.verify(:eddsa, :none, sig_base, signature, [pub, :ed25519])
  rescue
    _ -> false
  end

  defp claim_nonce(opts, with_dir, nonce, skew) do
    claim = opts[:claim_nonce]

    if claim != nil and is_binary(nonce) and
         not claim.("#{with_dir.directory}|#{with_dir.key_id}|#{nonce}", with_dir.expires * 1000 + skew * 1000) do
      fail(:replayed, with_dir)
    else
      Map.merge(%{signed: true, verified: true, nonce: if(is_binary(nonce), do: nonce)}, with_dir)
    end
  end

  # --- decision (allow and block lists) ---------------------------------------

  @doc """
  Turn a `verify/2` result into a decision. Only a VERIFIED directory can be allowed or blocked: an
  unsigned or failed request is `:unknown`, never trusted and never attributed to the directory it
  claimed. A block entry beats an allow entry. `policy` is `[allow: entries, block: entries]`, each
  entry a directory URL or bare host (normalised before comparing) or `%{directory: ..., name: ...}`.

  Returns `%{verified:, agent: nil | %{directory:, key_id:, name:}, tier: :allowed | :blocked | :verified | :unverified,
  decision: :allow | :block | :unknown, reason: (only when not verified)}`.
  """
  @spec decide(map(), keyword()) :: map()
  def decide(result, policy \\ []) do
    if not (result[:verified] == true and is_binary(result[:directory]) and is_binary(result[:key_id])) do
      base = %{verified: false, agent: nil, tier: :unverified, decision: :unknown}
      if result[:reason], do: Map.put(base, :reason, result[:reason]), else: base
    else
      match = fn list -> Enum.find(list || [], fn e -> normalize_directory(entry_directory(e)) == result.directory end) end
      blocked = match.(policy[:block])
      allowed = if blocked, do: nil, else: match.(policy[:allow])
      entry = blocked || allowed
      name = (entry && is_map(entry) && is_binary(entry[:name]) && String.trim(entry[:name])) || ""
      name = if name == "", do: URI.parse(result.directory).host || result.directory, else: name

      %{
        verified: true,
        agent: %{directory: result.directory, key_id: result.key_id, name: name},
        tier: cond do blocked -> :blocked; allowed -> :allowed; true -> :verified end,
        decision: cond do blocked -> :block; allowed -> :allow; true -> :unknown end
      }
    end
  end

  defp entry_directory(%{directory: d}), do: d
  defp entry_directory(d) when is_binary(d), do: d
  defp entry_directory(_), do: ""

  # --- signing (for bots and tests) -----------------------------------------

  @doc """
  Produce the three headers (`signature-agent`, `signature-input`, `signature`) for a request. Options:
  `:method`, `:url`, `:signature_agent` (the directory URL the bot publishes its keys under),
  `:private_key` (the 32-byte Ed25519 seed), `:created`, `:expires` (epoch seconds) (all required);
  `:headers` (a map), `:nonce`, `:label` (default `"sig1"`), `:components` (default `["@authority",
  "signature-agent"]`; must include both; use `{name, params}` for parameterised ones).
  """
  @spec sign_request(keyword()) :: %{String.t() => String.t()}
  def sign_request(opts) do
    label = Keyword.get(opts, :label, "sig1")
    components = Keyword.get(opts, :components, ["@authority", "signature-agent"])
    seed = Keyword.fetch!(opts, :private_key)
    {pub, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    key_id = jwk_thumbprint(%{"x" => b64url(pub)})
    agent_header = "\"" <> Keyword.fetch!(opts, :signature_agent) <> "\""

    params =
      "(" <> Enum.map_join(components, " ", &serialize_component_id/1) <> ")" <>
        ";created=#{Keyword.fetch!(opts, :created)};keyid=\"#{key_id}\";alg=\"ed25519\";expires=#{Keyword.fetch!(opts, :expires)}" <>
        if(opts[:nonce], do: ";nonce=\"#{opts[:nonce]}\"", else: "") <> ";tag=\"#{@tag}\""

    headers = Map.put(Map.new(opts[:headers] || %{}), "signature-agent", agent_header)

    case build_signature_base(%{method: Keyword.fetch!(opts, :method), url: Keyword.fetch!(opts, :url), headers: headers}, components, params) do
      {:ok, base} ->
        sig = :crypto.sign(:eddsa, :none, base, [seed, :ed25519])
        %{"signature-agent" => agent_header, "signature-input" => "#{label}=#{params}", "signature" => "#{label}=:#{Base.encode64(sig)}:"}

      {:error, e} ->
        raise ArgumentError, "Cannot sign: #{e}."
    end
  end

  defp b64url(bin), do: Base.url_encode64(bin, padding: false)
end

defmodule AtlasAuth.WebBotAuth.DirectoryCache do
  @moduledoc """
  A small in-memory cache of Web Bot Auth key directories (a `GenServer`). Hand `getter/1` to
  `AtlasAuth.WebBotAuth.verify/2` as `:get_keys`.

  Options: `:fetch_json` (required; `(url -> {:ok, decoded_json} | term)`: anything but `{:ok, _}`
  counts as a failed fetch), `:ttl_ms` (a fetched directory is trusted this long; default 10 minutes),
  `:failure_ttl_ms` (a failed fetch is remembered; 1 minute), `:refresh_cooldown_ms` (the least time
  between refreshes of one directory, so a bot cannot force a fetch per request; 1 minute),
  `:max_entries` (1000), `:now_ms`, `:name`.

  A failed refresh keeps serving the last good copy rather than dropping a working directory. The
  fetch runs inside the cache process, so use a fetch function with its own timeout.
  """
  use GenServer

  alias AtlasAuth.WebBotAuth

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, if(opts[:name], do: [name: opts[:name]], else: []))

  @doc "The `:get_keys` function for `AtlasAuth.WebBotAuth.verify/2`."
  @spec getter(GenServer.server()) :: (String.t(), boolean() -> [map()] | nil)
  def getter(server), do: fn url, refresh -> get_keys(server, url, refresh) end

  @doc "The keys of the directory at `url`, from cache when fresh; nil when unavailable."
  @spec get_keys(GenServer.server(), String.t(), boolean()) :: [map()] | nil
  def get_keys(server, url, refresh), do: GenServer.call(server, {:get_keys, url, refresh}, 30_000)

  @doc "Forget every cached directory."
  def clear(server), do: GenServer.call(server, :clear)

  @impl true
  def init(opts) do
    {:ok,
     %{
       fetch: Keyword.fetch!(opts, :fetch_json),
       ttl: Keyword.get(opts, :ttl_ms, 600_000),
       failure_ttl: Keyword.get(opts, :failure_ttl_ms, 60_000),
       cooldown: Keyword.get(opts, :refresh_cooldown_ms, 60_000),
       max: Keyword.get(opts, :max_entries, 1000),
       now: Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end),
       entries: %{}
     }}
  end

  @impl true
  def handle_call(:clear, _from, s), do: {:reply, :ok, %{s | entries: %{}}}

  def handle_call({:get_keys, url, refresh}, _from, s) do
    t = s.now.()
    hit = s.entries[url]
    ttl = if hit && hit.keys, do: s.ttl, else: s.failure_ttl

    if hit && t - hit.at < ttl && not (refresh && t - hit.fetched_at >= s.cooldown) do
      {:reply, hit.keys, s}
    else
      keys =
        try do
          case s.fetch.(url) do
            {:ok, doc} -> nonempty(WebBotAuth.parse_directory(doc))
            _ -> nil
          end
        rescue
          _ -> nil
        end

      kept = keys || (hit && hit.keys) || nil
      entries = if map_size(s.entries) >= s.max and not Map.has_key?(s.entries, url), do: evict_oldest(s.entries), else: s.entries
      {:reply, kept, %{s | entries: Map.put(entries, url, %{keys: kept, at: t, fetched_at: t})}}
    end
  end

  defp nonempty([]), do: nil
  defp nonempty(list), do: list

  defp evict_oldest(entries) do
    {oldest, _} = Enum.min_by(entries, fn {_, e} -> e.fetched_at end)
    Map.delete(entries, oldest)
  end
end

defmodule AtlasAuth.WebBotAuth.Verifier do
  @moduledoc """
  A Web Bot Auth verifier that runs inside your own server: no call to Atlas, directories cached in
  memory, allow and block lists applied. Start it once (it owns the directory cache and the replay set):

      {:ok, v} =
        AtlasAuth.WebBotAuth.Verifier.start_link(
          allow: [%{directory: "https://bot.example", name: "Example bot"}],
          block: ["https://bad.example"]
        )

      decision = AtlasAuth.WebBotAuth.Verifier.verify(v, %{method: conn.method, url: url, headers: conn.req_headers})
      decision.decision   # :allow | :block | :unknown

  Options: `:allow`, `:block` (see `AtlasAuth.WebBotAuth.decide/2`), `:fetch_json` (`url -> {:ok, json} | term`; the
  default uses `:httpc` over https only, no redirects, 5 seconds, a 64 KB cap, and refuses literal-address,
  `localhost` and single-label hosts, but it cannot pin the resolved address: pass your own function behind an
  SSRF-safe transport where that matters), `:ttl_ms`, `:refresh_cooldown_ms`, `:skew_seconds`,
  `:max_lifetime_seconds`, `:reject_replays` (refuse a signature whose nonce was seen before, in memory, per
  process; off by default because some bots reuse one signed request until it expires), `:now_ms`, `:name`.
  """
  use GenServer

  alias AtlasAuth.WebBotAuth
  alias AtlasAuth.WebBotAuth.DirectoryCache

  @max_bytes 64 * 1024

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, if(opts[:name], do: [name: opts[:name]], else: []))

  @doc "Verify and decide. Never raises on bad input. Runs in the caller; the server holds only the directory cache and the replay set."
  @spec verify(GenServer.server(), map()) :: map()
  def verify(server, req) do
    %{opts: opts, cache: cache, now: now} = GenServer.call(server, :config)
    claim = if opts[:reject_replays], do: fn key, exp -> GenServer.call(server, {:claim, key, exp}) end

    result =
      WebBotAuth.verify(
        req,
        [get_keys: DirectoryCache.getter(cache), now_ms: now.()] ++
          Keyword.take(opts, [:skew_seconds, :max_lifetime_seconds]) ++ if(claim, do: [claim_nonce: claim], else: [])
      )

    WebBotAuth.decide(result, allow: opts[:allow], block: opts[:block])
  end

  @doc "Forget every cached directory."
  def clear_cache(server), do: GenServer.call(server, :clear_cache)

  @impl true
  def init(opts) do
    now = Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end)

    {:ok, cache} =
      DirectoryCache.start_link(
        [fetch_json: opts[:fetch_json] || (&default_fetch/1), now_ms: now] ++ Keyword.take(opts, [:ttl_ms, :refresh_cooldown_ms])
      )

    {:ok, %{opts: opts, cache: cache, now: now, seen: %{}}}
  end

  @impl true
  def handle_call(:config, _from, s), do: {:reply, Map.take(s, [:opts, :cache, :now]), s}
  def handle_call(:clear_cache, _from, s), do: {:reply, DirectoryCache.clear(s.cache), s}

  def handle_call({:claim, key, exp}, _from, s) do
    t = s.now.()
    seen = if map_size(s.seen) > 5000, do: Map.reject(s.seen, fn {_, e} -> e <= t end), else: s.seen

    cond do
      # fail closed rather than grow without bound
      map_size(seen) > 20_000 -> {:reply, false, %{s | seen: seen}}
      (Map.get(seen, key) || 0) > t -> {:reply, false, %{s | seen: seen}}
      true -> {:reply, true, %{s | seen: Map.put(seen, key, exp)}}
    end
  end

  defp default_fetch(url) do
    with %URI{scheme: "https", host: host} <- URI.parse(url),
         false <- private_host?(host),
         {:ok, %{status: 200, body: body}} when byte_size(body) <= @max_bytes <-
           AtlasAuth.Http.request(:get, url, [{"accept", WebBotAuth.directory_media_type()}], nil, timeout_ms: 5000),
         {:ok, doc} <- Jason.decode(body) do
      {:ok, doc}
    else
      _ -> :error
    end
  end

  defp private_host?(host) when is_binary(host) do
    h = String.downcase(host)
    h == "localhost" or String.ends_with?(h, ".localhost") or String.contains?(h, ":") or Regex.match?(~r/\A\d{1,3}(\.\d{1,3}){3}\z/, h) or not String.contains?(h, ".")
  end

  defp private_host?(_), do: true
end
