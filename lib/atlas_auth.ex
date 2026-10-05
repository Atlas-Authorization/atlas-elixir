defmodule AtlasAuth do
  @moduledoc """
  Atlas backend SDK for Elixir — the Elixir peer of the Go, PHP, Rust and other
  Atlas server SDKs.

  It does one job: verify an Atlas session JWT locally, against the instance
  JWKS, without calling Atlas on the request hot path. See `AtlasAuth.Verifier`
  for the verification rules, `AtlasAuth.Claims` for the decoded token, and
  `AtlasAuth.Plug` / `AtlasAuth.Plug.RequireAuth` for the Plug/Phoenix
  integration.

  ## Quick start

      # In a Phoenix pipeline (router.ex):
      pipeline :api do
        plug AtlasAuth.Plug,
          jwks_url: "https://your-instance.atlas.example/.well-known/jwks.json",
          issuer: "https://your-instance.atlas.example"
        plug AtlasAuth.Plug.RequireAuth
      end

      # Or verify a token directly:
      {:ok, claims} = AtlasAuth.verify(token,
        jwks_url: jwks_url, issuer: issuer)
      claims.sub
      AtlasAuth.Claims.has_permission?(claims, "billing:read")
  """

  @doc "Delegates to `AtlasAuth.Verifier.verify/2`."
  defdelegate verify(token, opts \\ []), to: AtlasAuth.Verifier

  @doc "Delegates to `AtlasAuth.Verifier.authenticate_request/2`."
  defdelegate authenticate_request(headers, opts \\ []), to: AtlasAuth.Verifier
end
