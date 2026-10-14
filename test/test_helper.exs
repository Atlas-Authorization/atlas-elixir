# Generate the shared test signing key once, before any async test runs, so two
# tests racing on first use can never sign with a key the JWKS does not serve.
AtlasAuth.TokenHelper.private_jwk()

ExUnit.start()
