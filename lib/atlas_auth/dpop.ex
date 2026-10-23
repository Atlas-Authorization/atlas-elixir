defmodule AtlasAuth.DPoP do
  @moduledoc """
  DPoP proof verification (RFC 9449) for `AtlasAuth.AccessToken`.

  A DPoP-bound access token carries `cnf.jkt`, the RFC 7638 thumbprint of the
  client's key. Each request must then arrive with the `DPoP` scheme and a
  `DPoP` header: a short-lived JWT (`typ` `dpop+jwt`) signed by that key,
  carrying the public key itself, the request method (`htm`) and URL (`htu`),
  the hash of the access token (`ath`), a unique `jti`, and the server's nonce
  when the API asks for one.
  """

  @proof_max_age_seconds 300
  @clock_skew_seconds 5
  @algs ~w(ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA)
  @private_members ~w(d k p q dp dq qi)
  @ec_curves %{"ES256" => {"P-256", 32}, "ES384" => {"P-384", 48}, "ES512" => {"P-521", 66}}

  @doc "The JWS algorithms accepted on a DPoP proof (and advertised in challenges and metadata)."
  @spec algs() :: [String.t()]
  def algs, do: @algs

  @doc "How old a DPoP proof may be, in seconds."
  def proof_max_age_seconds, do: @proof_max_age_seconds

  @doc "The `ath` a DPoP proof carries for `token`: base64url(SHA-256(token))."
  @spec access_token_hash(String.t()) :: String.t()
  def access_token_hash(token),
    do: Base.url_encode64(:crypto.hash(:sha256, token), padding: false)

  @doc """
  The RFC 7638 SHA-256 thumbprint (base64url) of a public EC, RSA or OKP JWK:
  the `cnf.jkt` a DPoP-bound token carries. `nil` for an unsupported or
  incomplete key.
  """
  @spec jwk_thumbprint(map()) :: String.t() | nil
  def jwk_thumbprint(jwk) when is_map(jwk) do
    members =
      case jwk["kty"] do
        "EC" -> ~w(crv kty x y)
        "RSA" -> ~w(e kty n)
        "OKP" -> ~w(crv kty x)
        _ -> nil
      end

    with members when is_list(members) <- members,
         true <- Enum.all?(members, &(is_binary(jwk[&1]) and jwk[&1] != "")) do
      body =
        Enum.map_join(members, ",", fn m -> Jason.encode!(m) <> ":" <> Jason.encode!(jwk[m]) end)

      Base.url_encode64(:crypto.hash(:sha256, "{" <> body <> "}"), padding: false)
    else
      _ -> nil
    end
  end

  def jwk_thumbprint(_), do: nil

  @doc """
  Reduce a URL to the form RFC 9449 §4.3 compares `htu` in: scheme and host
  lower-cased, the default port dropped, an empty path as `/`, no query or
  fragment. `nil` for anything but an absolute http(s) URL.
  """
  @spec normalize_htu(term()) :: String.t() | nil
  def normalize_htu(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host} = u
      when is_binary(scheme) and is_binary(host) and host != "" ->
        scheme = String.downcase(scheme)

        if scheme in ["http", "https"] do
          host = String.downcase(host)
          host = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

          default? =
            (scheme == "https" and u.port == 443) or (scheme == "http" and u.port == 80) or
              u.port == nil

          port = if default?, do: "", else: ":#{u.port}"
          path = if u.path in [nil, ""], do: "/", else: u.path
          scheme <> "://" <> host <> port <> path
        end

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  def normalize_htu(_), do: nil

  @doc false
  # Check one proof. `:ok` when it is good, else `{:error, error, description}`
  # with error "invalid_dpop_proof" or "use_dpop_nonce".
  def check_proof(proof, ctx) do
    bad = fn d -> {:error, "invalid_dpop_proof", d} end

    with {:parts, [h64, p64, s64]} <- {:parts, String.split(proof, ".")},
         {:header, %{} = header} <- {:header, json_segment(h64)},
         {:typ, "dpop+jwt"} <- {:typ, header["typ"]},
         {:alg, alg} when alg in @algs <- {:alg, header["alg"]},
         {:jwk, %{} = jwk} <- {:jwk, header["jwk"]},
         {:public, true} <- {:public, not Enum.any?(@private_members, &Map.has_key?(jwk, &1))},
         {:sig, true} <- {:sig, verify_signature(jwk, alg, proof, s64)},
         {:payload, %{} = p} <- {:payload, json_segment(p64)},
         {:jkt, true} <- {:jkt, secure_compare(jwk_thumbprint(jwk), ctx.jkt)},
         {:htm, true} <- {:htm, p["htm"] == ctx.method},
         {:htu, true} <- {:htu, htu_ok?(p["htu"], ctx)},
         {:iat, true} <- {:iat, iat_ok?(p, ctx.now_ms)},
         {:ath, true} <- {:ath, p["ath"] == access_token_hash(ctx.token)},
         {:jti, jti} when is_binary(jti) and jti != "" <- {:jti, p["jti"]},
         {:nonce, true} <- {:nonce, nonce_ok?(p["nonce"], ctx.nonces)},
         {:replay, true} <-
           {:replay,
            claim(
              ctx.replay,
              ctx.jkt <> ":" <> jti,
              round(p["iat"] * 1000) + @proof_max_age_seconds * 1000
            )} do
      :ok
    else
      {:parts, _} ->
        bad.("The DPoP proof is malformed.")

      {:header, _} ->
        bad.("The DPoP proof is malformed.")

      {:typ, _} ->
        bad.("The DPoP proof must have typ dpop+jwt.")

      {:alg, _} ->
        bad.("The DPoP proof uses an unsupported algorithm.")

      {:jwk, _} ->
        bad.("The DPoP proof must carry its public key.")

      {:public, _} ->
        bad.("The DPoP proof key must be a public key.")

      {:sig, _} ->
        bad.("The DPoP proof signature is invalid.")

      {:payload, _} ->
        bad.("The DPoP proof is malformed.")

      {:jkt, _} ->
        bad.("The DPoP proof key does not match the token binding.")

      {:htm, _} ->
        bad.("The DPoP proof htm does not match the request method.")

      {:htu, _} ->
        bad.("The DPoP proof htu does not match the request URL.")

      {:iat, _} ->
        bad.("The DPoP proof is too old or from the future.")

      {:ath, _} ->
        bad.("The DPoP proof ath does not match the access token.")

      {:jti, _} ->
        bad.("The DPoP proof needs a jti.")

      {:nonce, _} ->
        {:error, "use_dpop_nonce",
         "The DPoP proof must carry the nonce from the DPoP-Nonce header."}

      {:replay, _} ->
        bad.("The DPoP proof has already been used.")
    end
  end

  defp json_segment(segment) do
    with {:ok, raw} <- Base.url_decode64(segment, padding: false),
         {:ok, %{} = map} <- Jason.decode(raw) do
      map
    else
      _ -> nil
    end
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  defp secure_compare(_, _), do: false

  defp htu_ok?(htu, ctx) do
    target =
      cond do
        String.match?(ctx.url, ~r{^https?://}i) ->
          ctx.url

        is_binary(ctx.public_origin) and String.starts_with?(ctx.url, "/") ->
          String.trim_trailing(ctx.public_origin, "/") <> ctx.url

        true ->
          nil
      end

    expected = normalize_htu(target)
    expected != nil and normalize_htu(htu) == expected
  end

  defp iat_ok?(p, now_ms) do
    now = now_ms / 1000
    iat = p["iat"]
    exp = p["exp"]

    is_number(iat) and iat <= now + @clock_skew_seconds and now - iat <= @proof_max_age_seconds and
      not (is_number(exp) and now >= exp + @clock_skew_seconds)
  end

  defp nonce_ok?(_nonce, nil), do: true

  defp nonce_ok?(nonce, source) when is_binary(nonce) and nonce != "",
    do: nonce_valid?(source, nonce)

  defp nonce_ok?(_, _), do: false

  @doc false
  def nonce_current(nil), do: nil
  def nonce_current(%module{} = source), do: module.current(source)

  defp nonce_valid?(%module{} = source, nonce), do: module.valid?(source, nonce)

  defp claim(store, key, expires_at_ms) when is_function(store, 2),
    do: store.(key, expires_at_ms) == true

  defp claim(store, key, expires_at_ms) when is_atom(store),
    do: store.claim(key, expires_at_ms) == true

  defp verify_signature(jwk, alg, proof, s64) do
    with true <- not (is_binary(jwk["alg"]) and jwk["alg"] != "" and jwk["alg"] != alg),
         true <- key_fits?(jwk, alg),
         {:ok, _} <- Base.url_decode64(s64, padding: false) do
      case JOSE.JWS.verify_strict(JOSE.JWK.from_map(jwk), [alg], proof) do
        {true, _payload, _jws} -> true
        _ -> false
      end
    else
      _ -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp key_fits?(jwk, "EdDSA"),
    do: jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and decoded_size(jwk["x"]) == 32

  defp key_fits?(jwk, "ES" <> _ = alg) do
    {crv, size} = @ec_curves[alg]

    jwk["kty"] == "EC" and jwk["crv"] == crv and decoded_size(jwk["x"]) == size and
      decoded_size(jwk["y"]) == size
  end

  defp key_fits?(jwk, _rsa_alg) do
    n =
      case Base.url_decode64(to_string(jwk["n"]), padding: false) do
        {:ok, bytes} -> bytes |> :binary.bin_to_list() |> Enum.drop_while(&(&1 == 0)) |> length()
        _ -> 0
      end

    e = decoded_size(jwk["e"])
    jwk["kty"] == "RSA" and n >= 256 and is_integer(e) and e in 1..4
  end

  defp decoded_size(v) when is_binary(v) do
    case Base.url_decode64(v, padding: false) do
      {:ok, b} -> byte_size(b)
      _ -> nil
    end
  end

  defp decoded_size(_), do: nil
end

defmodule AtlasAuth.DPoP.ReplayStore do
  @moduledoc """
  Guards against a DPoP proof being used twice. Back it with something every
  node of your API shares (Redis `SET key 1 NX PX ttl`, a unique database key)
  when it runs on more than one; `AtlasAuth.DPoP.MemoryReplayStore` protects
  one node. Pass the module as `:dpop_replay_store` (or a 2-arity function).
  """

  @doc "Record `key` until `expires_at_ms`; `true` the first time, `false` on a replay."
  @callback claim(key :: String.t(), expires_at_ms :: integer()) :: boolean()
end

defmodule AtlasAuth.DPoP.MemoryReplayStore do
  @moduledoc """
  The node-local `AtlasAuth.DPoP.ReplayStore`: a public ETS table owned by a
  process under the `:atlas_auth` application. Entries live until they expire;
  when the table holds more than 10 000 entries, expired ones are swept.
  """
  @behaviour AtlasAuth.DPoP.ReplayStore
  use GenServer

  @table :atlas_auth_dpop_jti
  @max 10_000

  def start_link(_ \\ []), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl GenServer
  def init(nil) do
    :ets.new(@table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    {:ok, nil}
  end

  @impl AtlasAuth.DPoP.ReplayStore
  def claim(key, expires_at_ms), do: claim(key, expires_at_ms, System.system_time(:millisecond))

  @doc false
  def claim(key, expires_at_ms, now_ms) do
    case :ets.lookup(@table, key) do
      [{^key, exp}] when exp > now_ms ->
        false

      [{^key, _expired}] ->
        :ets.insert(@table, {key, expires_at_ms})
        true

      [] ->
        inserted = :ets.insert_new(@table, {key, expires_at_ms})
        if inserted and :ets.info(@table, :size) > @max, do: sweep(now_ms)
        inserted
    end
  end

  @doc false
  def sweep(now_ms),
    do: :ets.select_delete(@table, [{{:_, :"$1"}, [{:"=<", :"$1", now_ms}], [true]}])
end

defmodule AtlasAuth.DPoP.HmacNonce do
  @moduledoc """
  Server nonces for DPoP (RFC 9449 §8) derived from a secret and the clock: a
  nonce is good for the window it was issued in and the next one, so every node
  sharing the secret agrees without shared state. Pass it as `:dpop_nonces`.

  Any struct whose module defines `current/1` and `valid?/2` works in its place.
  """
  @enforce_keys [:secret, :window_ms]
  defstruct [:secret, :window_ms, now_ms: nil]

  @type t :: %__MODULE__{
          secret: binary(),
          window_ms: pos_integer(),
          now_ms: (() -> integer()) | nil
        }

  @doc "`secret` must be at least 32 bytes. Options: `:window_seconds` (300), `:now_ms` (a clock fun, for tests)."
  @spec new(binary(), keyword()) :: t()
  def new(secret, opts \\ []) when is_binary(secret) do
    if byte_size(secret) < 32,
      do: raise(ArgumentError, "The DPoP nonce secret must be at least 32 bytes.")

    window = Keyword.get(opts, :window_seconds, 300)

    if not is_integer(window) or window <= 0,
      do: raise(ArgumentError, "The DPoP nonce window must be positive.")

    %__MODULE__{secret: secret, window_ms: window * 1000, now_ms: Keyword.get(opts, :now_ms)}
  end

  @doc "The nonce to send in the `DPoP-Nonce` header."
  @spec current(t()) :: String.t()
  def current(%__MODULE__{} = s), do: at(s, epoch(s))

  @doc "Whether `nonce` is still in force."
  @spec valid?(t(), String.t()) :: boolean()
  def valid?(%__MODULE__{} = s, nonce) when is_binary(nonce) do
    e = epoch(s)

    Enum.any?(
      [at(s, e), at(s, e - 1)],
      &(byte_size(&1) == byte_size(nonce) and :crypto.hash_equals(&1, nonce))
    )
  end

  def valid?(_, _), do: false

  defp epoch(%{now_ms: nil, window_ms: w}), do: div(System.system_time(:millisecond), w)
  defp epoch(%{now_ms: f, window_ms: w}), do: div(f.(), w)

  defp at(%{secret: secret}, epoch),
    do:
      Base.url_encode64(
        :crypto.mac(:hmac, :sha256, secret, "atlas-dpop-nonce:" <> <<epoch::signed-64>>),
        padding: false
      )
end
