defmodule AtlasAuth.MixProject do
  use Mix.Project

  @version "0.8.0"
  @source_url "https://github.com/Atlas-Authorization/atlas-elixir"

  def project do
    [
      app: :atlas_auth,
      version: @version,
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      name: "AtlasAuth",
      source_url: @source_url,
      docs: docs()
    ]
  end

  # :inets/:ssl/:public_key back the default (zero-dependency) JWKS fetcher and
  # RS256 verification; a consumer who injects their own fetcher never calls them.
  def application do
    [
      extra_applications: [:logger, :inets, :ssl, :public_key, :crypto],
      mod: {AtlasAuth.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # RS256 / JWKS primitives. `jose` is the de-facto JOSE implementation for
      # the BEAM and the same one Phoenix/Guardian ecosystems lean on.
      {:jose, "~> 1.11"},
      # JSON for JWKS decoding and JOSE's JSON backend. Small, ubiquitous.
      {:jason, "~> 1.4"},
      # Plug is a LIGHT dependency and the plugs below work in any Plug/Phoenix
      # app, so it is optional: a consumer who only wants the verifier never
      # pulls it in, while this library still compiles its plugs against it.
      {:plug, "~> 1.14", optional: true},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    "The official Elixir backend SDK for Atlas — local RS256 session-token " <>
      "verification against the instance JWKS, with a Plug/Phoenix integration. " <>
      "The Elixir peer of the Go, PHP, Rust and other Atlas server SDKs."
  end

  defp package do
    [
      name: "atlas_auth",
      licenses: ["MIT"],
      maintainers: ["Atlas"],
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE .formatter.exs),
      links: %{
        "GitHub" => @source_url,
        "Atlas" => "https://atlasauth.net"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}"
    ]
  end
end
