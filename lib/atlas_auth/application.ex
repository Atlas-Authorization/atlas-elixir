defmodule AtlasAuth.Application do
  @moduledoc """
  The OTP application. Its only child is `AtlasAuth.JWKSCache`, the single
  in-process JWKS cache shared by every verifier in the VM.

  WHY one shared, supervised process rather than a cache per verifier: the whole
  point of the cache is to be a *process-wide* amortization of JWKS fetches and,
  more importantly, a process-wide rate limiter on refetches (see
  `AtlasAuth.JWKSCache`). A cache that lived inside each short-lived request would
  rate-limit nothing. Keying the state by URL inside one GenServer means every
  caller for a given instance shares one cached key set and one throttle window.
  """
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      AtlasAuth.JWKSCache,
      # Owns the ETS table behind the default DPoP proof replay store.
      AtlasAuth.DPoP.MemoryReplayStore,
      # Owns the ETS table behind the opaque-token introspection cache.
      AtlasAuth.Introspection,
      # Owns the ETS table behind the legacy-issuer subject cache.
      AtlasAuth.LegacyIssuers
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: AtlasAuth.Supervisor)
  end
end
