defmodule AtlasAuth.MachineClient.Error do
  @moduledoc "Atlas refused a machine request. `:status` is 0 for a client-side problem; `:code` is the machine-readable error code when there was one."
  defexception [:status, :code, :message]
end

defmodule AtlasAuth.MachineClient.Store do
  @moduledoc """
  Where a machine keeps its identity between runs (a map with `\"issuer\"`, `\"machine_id\"`,
  `\"private_key_pem\"`, `\"public_key_pem\"`, `\"enrolled_at\"`). A store is a `{module, ref}` pair.
  The private key never leaves it.
  """
  @callback load(ref :: term()) :: map() | nil
  @callback save(ref :: term(), identity :: map()) :: :ok
  @callback clear(ref :: term()) :: :ok
end

defmodule AtlasAuth.MachineClient.FileStore do
  @moduledoc "A store backed by one JSON file, written 0600 in a 0700 directory. `ref` is the file path."
  @behaviour AtlasAuth.MachineClient.Store

  @impl true
  def load(path) do
    with {:ok, raw} <- File.read(path),
         {:ok, %{} = identity} <- Jason.decode(raw) do
      identity
    else
      _ -> nil
    end
  end

  @impl true
  def save(path, identity) do
    dir = Path.dirname(path)
    File.mkdir_p!(dir)
    _ = File.chmod(dir, 0o700)
    tmp = "#{path}.#{System.unique_integer([:positive])}.tmp"
    File.write!(tmp, Jason.encode!(identity))
    File.chmod!(tmp, 0o600)
    File.rename!(tmp, path)
    :ok
  end

  @impl true
  def clear(path) do
    _ = File.rm(path)
    :ok
  end
end

defmodule AtlasAuth.MachineClient.MemoryStore do
  @moduledoc "A store that forgets on exit (tests, short-lived jobs that enrol every run). `ref` is an `Agent`."
  @behaviour AtlasAuth.MachineClient.Store

  @doc "Start the store, optionally holding `identity` already."
  def start_link(identity \\ nil), do: Agent.start_link(fn -> identity end)

  @impl true
  def load(ref), do: Agent.get(ref, & &1)
  @impl true
  def save(ref, identity), do: Agent.update(ref, fn _ -> identity end)
  @impl true
  def clear(ref), do: Agent.update(ref, fn _ -> nil end)
end

defmodule AtlasAuth.MachineClient do
  @moduledoc """
  The device side of machine enrolment, for a service or device of your own: generate an
  Ed25519 key, enrol with a token or a short code, then trade a signed challenge for
  short-lived machine tokens, cached until shortly before they expire.

      {:ok, client} =
        AtlasAuth.MachineClient.start_link(
          issuer: "https://id.example.com",
          store: {AtlasAuth.MachineClient.FileStore, "/var/lib/myservice/machine.json"}
        )

      {:ok, _} = AtlasAuth.MachineClient.enroll(client, credential: "met_...", name: "worker-1")
      {:ok, %{token: token}} = AtlasAuth.MachineClient.get_token(client, audience: "https://api.example.com")

  Options for `start_link/1`: `:issuer` and `:store` (required); `:poster`
  (`(url, headers, body -> {:ok, status, body} | {:error, term})`, default `:httpc`); `:now_ms`
  (zero-arity clock); `:refresh_skew_seconds` (fetch a new token this long before the cached one
  expires; default 60); `:dpop_key` (`:generate` for Ed25519, `{:generate, :es256 | :es384}`, or a PEM: an Ed25519 PKCS#8 key or a P-256 / P-384 EC key) to bind every token to a
  DPoP key (RFC 9449), needed when the machine's token binding is `dpop`; `:name`.

  The wire format is fixed: the signature over the challenge is pure Ed25519 over the nonce's
  UTF-8 bytes, base64url without padding (`sign_challenge/2`).
  """
  use GenServer

  alias AtlasAuth.MachineClient.Error

  # Fixed DER prefixes of an Ed25519 PKCS#8 private key (RFC 8410) and SPKI public key.
  @pkcs8 <<0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20>>
  @spki <<0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00>>

  # --- keys -----------------------------------------------------------------

  @doc "A new Ed25519 keypair as `{public_key_pem, private_key_pem}` (SPKI and PKCS#8)."
  @spec generate_keypair() :: {String.t(), String.t()}
  def generate_keypair do
    {pub, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {pem("PUBLIC KEY", @spki <> pub), pem("PRIVATE KEY", @pkcs8 <> seed)}
  end

  @doc "`base64url(sign(private_key, nonce))`, no padding: pure Ed25519 over the nonce's UTF-8 bytes."
  @spec sign_challenge(String.t(), String.t()) :: String.t()
  def sign_challenge(private_key_pem, nonce) do
    {:ok, seed} = seed_of(private_key_pem)
    :crypto.sign(:eddsa, :none, nonce, [seed, :ed25519]) |> Base.url_encode64(padding: false)
  end

  @doc "The SPKI public key PEM re-derived from a private key PEM (to check a store was not swapped)."
  @spec public_key_pem_of(String.t()) :: String.t()
  def public_key_pem_of(private_key_pem) do
    {:ok, seed} = seed_of(private_key_pem)
    {pub, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    pem("PUBLIC KEY", @spki <> pub)
  end

  defp seed_of(pem) do
    body = pem |> String.split("\n", trim: true) |> Enum.reject(&String.starts_with?(&1, "-----")) |> Enum.join()

    with {:ok, der} <- Base.decode64(body),
         <<@pkcs8, seed::binary-size(32)>> <- der do
      {:ok, seed}
    else
      _ -> {:error, :invalid_key}
    end
  end

  defp pem(label, der) do
    lines = der |> Base.encode64() |> chunk(64) |> Enum.join("\n")
    "-----BEGIN #{label}-----\n#{lines}\n-----END #{label}-----\n"
  end

  defp chunk("", _), do: []
  defp chunk(s, n) when byte_size(s) <= n, do: [s]
  defp chunk(s, n), do: [binary_part(s, 0, n) | chunk(binary_part(s, n, byte_size(s) - n), n)]

  # --- API ------------------------------------------------------------------

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, if(opts[:name], do: [name: opts[:name]], else: []))

  @doc """
  Generate a key, enrol with a token or short code, and store the identity. The private key is created
  here and only its public half is sent. Options: `:credential` (a `met_` token or `XXXX-XXXX` code) and
  `:name` (required), `:metadata`, `:device_key`. Returns `{:ok, %{machine_id:, status:, approval_required:}}`.
  """
  @spec enroll(GenServer.server(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def enroll(server, opts), do: GenServer.call(server, {:enroll, opts}, 60_000)

  @doc "Whether this machine holds an identity for its issuer."
  @spec enrolled?(GenServer.server()) :: boolean()
  def enrolled?(server), do: machine_id(server) != nil

  @doc "The enrolled machine's id, or nil."
  @spec machine_id(GenServer.server()) :: String.t() | nil
  def machine_id(server), do: GenServer.call(server, :machine_id)

  @doc """
  A machine token for this request, from the cache while it has more than the refresh skew left. `req`
  takes `:audience`, `:scopes`, `:scope_presets`, `:organization_id`. Returns
  `{:ok, %{token:, token_type: "Bearer" | "DPoP", expires_at:, audience:, scope:, constraints:, organization_id:}}`.
  """
  @spec get_token(GenServer.server(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def get_token(server, req \\ []), do: GenServer.call(server, {:get_token, req}, 60_000)

  @doc """
  A DPoP proof for one call to your API with a token this client minted: send `Authorization: DPoP <token>`
  plus `DPoP: <proof>`. `req` takes `:token`, `:method`, `:url`, `:nonce`. Needs the `:dpop_key` option.
  """
  @spec dpop_proof(GenServer.server(), keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def dpop_proof(server, req), do: GenServer.call(server, {:dpop_proof, req})

  @doc "The thumbprint (`cnf.jkt`) tokens minted by this client carry, or nil without a `:dpop_key`."
  @spec dpop_thumbprint(GenServer.server()) :: String.t() | nil
  def dpop_thumbprint(server), do: GenServer.call(server, :dpop_thumbprint)

  @doc "Forget cached tokens (the stored identity stays)."
  @spec clear_tokens(GenServer.server()) :: :ok
  def clear_tokens(server), do: GenServer.call(server, :clear_tokens)

  @doc "Forget the identity too: the machine must enrol again."
  @spec reset(GenServer.server()) :: :ok
  def reset(server), do: GenServer.call(server, :reset)

  # --- server ---------------------------------------------------------------

  @impl true
  def init(opts) do
    dpop =
      case opts[:dpop_key] do
        nil -> nil
        :generate -> generate_keypair() |> elem(1) |> dpop_state()
        {:generate, alg} when alg in [:es256, :es384] -> generate_dpop_key(alg) |> dpop_state()
        pem when is_binary(pem) -> dpop_state(pem)
      end

    {:ok,
     %{
       issuer: opts |> Keyword.fetch!(:issuer) |> String.trim_trailing("/"),
       store: Keyword.fetch!(opts, :store),
       poster: Keyword.get(opts, :poster, &AtlasAuth.Introspection.default_post/3),
       now: Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end),
       skew_ms: Keyword.get(opts, :refresh_skew_seconds, 60) * 1000,
       cache: %{},
       dpop: dpop
     }}
  end

  @ec_curves %{
    {1, 2, 840, 10045, 3, 1, 7} => {:secp256r1, "ES256", "P-256", 32, :sha256},
    {1, 3, 132, 0, 34} => {:secp384r1, "ES384", "P-384", 48, :sha384}
  }

  @doc "A new EC DPoP key (`:es256` or `:es384`) as a SEC1 PEM. Keep it as safely as the machine's own key."
  @spec generate_dpop_key(:es256 | :es384) :: String.t()
  def generate_dpop_key(alg) do
    curve = if alg == :es384, do: :secp384r1, else: :secp256r1
    rec = :public_key.generate_key({:namedCurve, curve})
    :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, rec)])
  end

  defp dpop_state(pem) do
    case seed_of(pem) do
      {:ok, seed} ->
        {pub, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
        jwk = %{"kty" => "OKP", "crv" => "Ed25519", "x" => Base.url_encode64(pub, padding: false)}
        %{alg: "EdDSA", jwk: jwk, sign: fn input -> :crypto.sign(:eddsa, :none, input, [seed, :ed25519]) end}

      _ ->
        ec_state(pem)
    end
  end

  # A P-256 / P-384 EC key (SEC1 or PKCS#8 PEM); the proof signature is the raw r||s form JWS uses.
  defp ec_state(pem) do
    with [entry | _] <- :public_key.pem_decode(pem),
         {:ECPrivateKey, _, priv, {:namedCurve, oid}, _, _} <- :public_key.pem_entry_decode(entry),
         {curve, alg, crv, size, hash} <- Map.get(@ec_curves, oid) do
      {<<4, x::binary-size(size), y::binary-size(size)>>, _} = :crypto.generate_key(:ecdh, curve, priv)

      %{
        alg: alg,
        jwk: %{"kty" => "EC", "crv" => crv, "x" => Base.url_encode64(x, padding: false), "y" => Base.url_encode64(y, padding: false)},
        sign: fn input ->
          der = :crypto.sign(:ecdsa, hash, input, [priv, curve])
          {:"ECDSA-Sig-Value", r, sv} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
          <<r::unsigned-big-integer-size(size * 8), sv::unsigned-big-integer-size(size * 8)>>
        end
      }
    else
      _ -> raise ArgumentError, "A DPoP key must be an Ed25519 PKCS#8 PEM or a P-256 / P-384 EC key."
    end
  end

  @impl true
  def handle_call({:enroll, opts}, _from, s) do
    {public_pem, private_pem} = generate_keypair()

    body =
      %{
        enrolment_token: String.trim(Keyword.fetch!(opts, :credential)),
        name: Keyword.fetch!(opts, :name),
        public_key_pem: public_pem
      }
      |> put_if(:metadata, opts[:metadata])
      |> put_if(:device_key, opts[:device_key])

    case post(s, "/v1/machines/enroll", body, false) do
      {:ok, res} ->
        identity = %{
          "issuer" => s.issuer,
          "machine_id" => res["id"],
          "private_key_pem" => private_pem,
          "public_key_pem" => public_pem,
          "enrolled_at" => res["enrolled_at"] || s.now.()
        }

        :ok = store(s, :save, [identity])
        {:reply, {:ok, %{machine_id: res["id"], status: res["status"], approval_required: res["approval_required"] == true}}, %{s | cache: %{}}}

      {:error, e} ->
        {:reply, {:error, e}, s}
    end
  end

  def handle_call(:machine_id, _from, s), do: {:reply, identity(s) && identity(s)["machine_id"], s}

  def handle_call({:get_token, req}, _from, s) do
    key = cache_key(req)

    hit = s.cache[key]

    if hit && hit.expires_at - s.skew_ms > s.now.() do
      {:reply, {:ok, hit}, s}
    else
      case mint(s, req) do
        {:ok, token} -> {:reply, {:ok, token}, %{s | cache: Map.put(s.cache, key, token)}}
        {:error, e} -> {:reply, {:error, e}, s}
      end
    end
  end

  def handle_call({:dpop_proof, req}, _from, %{dpop: nil} = s) do
    _ = req
    {:reply, {:error, %Error{status: 0, code: "dpop_not_configured", message: "Start the client with the :dpop_key option to sign DPoP proofs."}}, s}
  end

  def handle_call({:dpop_proof, req}, _from, s) do
    {:reply, {:ok, proof(s, req[:method], req[:url], req[:token], req[:nonce])}, s}
  end

  def handle_call(:dpop_thumbprint, _from, %{dpop: nil} = s), do: {:reply, nil, s}
  def handle_call(:dpop_thumbprint, _from, s), do: {:reply, AtlasAuth.DPoP.jwk_thumbprint(s.dpop.jwk), s}
  def handle_call(:clear_tokens, _from, s), do: {:reply, :ok, %{s | cache: %{}}}

  def handle_call(:reset, _from, s) do
    :ok = store(s, :clear, [])
    {:reply, :ok, %{s | cache: %{}}}
  end

  # The stored identity, or nil before enrolment (or when it belongs to another issuer).
  defp identity(s) do
    case store(s, :load, []) do
      %{"issuer" => issuer} = i when issuer == s.issuer -> i
      _ -> nil
    end
  end

  defp mint(s, req) do
    case identity(s) do
      nil ->
        {:error, %Error{status: 0, code: "not_enrolled", message: "This machine is not enrolled. Call enroll/2 first."}}

      id ->
        with {:ok, %{"nonce" => nonce}} <- post(s, "/v1/machines/challenge", %{machine_id: id["machine_id"]}, false),
             {:ok, res} <- post(s, "/v1/machines/token", token_body(id, nonce, req), true) do
          {:ok,
           %{
             token: res["token"],
             token_type: if(res["token_type"] == "DPoP", do: "DPoP", else: "Bearer"),
             expires_at: s.now.() + (res["expires_in"] || 0) * 1000,
             audience: res["audience"],
             scope: res["scope"],
             constraints: res["constraints"],
             organization_id: res["organization_id"]
           }}
        end
    end
  end

  defp token_body(id, nonce, req) do
    %{
      machine_id: id["machine_id"],
      nonce: nonce,
      signature: sign_challenge(id["private_key_pem"], nonce)
    }
    |> put_if(:audience, req[:audience])
    |> put_if(:scopes, req[:scopes])
    |> put_if(:scope_presets, req[:scope_presets])
    |> put_if(:organization_id, req[:organization_id])
  end

  defp put_if(map, _k, nil), do: map
  defp put_if(map, k, v), do: Map.put(map, k, v)

  defp cache_key(req) do
    {req[:audience] || "", Enum.sort(req[:scopes] || []), Enum.sort(req[:scope_presets] || []), req[:organization_id] || ""}
  end

  defp post(s, path, body, with_proof) do
    url = s.issuer <> path
    headers = [{"content-type", "application/json"}] ++ if(with_proof and s.dpop, do: [{"dpop", proof(s, "POST", url, nil, nil)}], else: [])

    case s.poster.(url, headers, Jason.encode!(body)) do
      {:ok, status, raw} when status in 200..299 ->
        case Jason.decode(raw) do
          {:ok, %{} = json} -> {:ok, json}
          _ -> {:ok, %{}}
        end

      {:ok, status, raw} ->
        json = case Jason.decode(raw) do
          {:ok, %{} = j} -> j
          _ -> %{}
        end

        first = case json["errors"] do
          [%{} = f | _] -> f
          _ -> %{}
        end

        {:error,
         %Error{
           status: status,
           code: first["code"] || if(is_binary(json["code"]), do: json["code"]),
           message: first["message"] || json["message"] || "Request failed with status #{status}."
         }}

      {:error, reason} ->
        {:error, %Error{status: 0, code: "transport_error", message: "request failed: #{inspect(reason)}"}}
    end
  end

  defp proof(s, method, url, token, nonce) do
    header = %{"typ" => "dpop+jwt", "alg" => s.dpop.alg, "jwk" => s.dpop.jwk}

    claims =
      %{
        "jti" => :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false),
        "htm" => String.upcase(method),
        "htu" => AtlasAuth.DPoP.normalize_htu(url),
        "iat" => div(s.now.(), 1000)
      }
      |> put_if("ath", token && AtlasAuth.DPoP.access_token_hash(token))
      |> put_if("nonce", nonce)

    input = b64(Jason.encode!(header)) <> "." <> b64(Jason.encode!(claims))
    sig = s.dpop.sign.(input)
    input <> "." <> b64(sig)
  end

  defp b64(bin), do: Base.url_encode64(bin, padding: false)
  defp store(%{store: {mod, ref}}, fun, args), do: apply(mod, fun, [ref | args])
end
