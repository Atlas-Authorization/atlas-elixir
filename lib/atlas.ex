defmodule Atlas do
  @moduledoc """
  The Atlas Backend API client: one module per resource (`Atlas.Users`,
  `Atlas.Organizations`, `Atlas.Sessions`, ...), every public Backend operation.

      client = Atlas.new(System.fetch_env!("ATLAS_SECRET_KEY"))

      {:ok, page} = Atlas.Users.list(client, params: [limit: 20])
      {:ok, user} = Atlas.Users.get(client, "user_123")

      # Cursor-paginated lists also come as lazy streams.
      client |> Atlas.Users.stream_list() |> Stream.take(100) |> Enum.to_list()

      case Atlas.Users.create(client, %{email_address: "a@example.com"}, idempotency_key: "k1") do
        {:ok, user} -> user
        {:error, %Atlas.Error{code: code, message: message}} -> {code, message}
      end

  Session-token verification (`AtlasAuth.verify/2`) is a separate, local
  module and does not need a client.
  """

  @doc "Build a client from a secret key. See `Atlas.Client.new/2`."
  defdelegate new(secret_key, opts \\ []), to: Atlas.Client
end
