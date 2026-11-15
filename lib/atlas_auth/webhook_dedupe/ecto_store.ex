if Code.ensure_loaded?(Ecto.Adapters.SQL) do
  defmodule AtlasAuth.WebhookDedupe.EctoStore do
    @moduledoc """
    A `AtlasAuth.WebhookDedupe` store on SQL through Ecto (`:ecto_sql` is an optional dependency).
    The store is `{AtlasAuth.WebhookDedupe.EctoStore, %{repo: MyApp.Repo, dialect: :postgres}}`;
    `dialect` is `:postgres` (default), `:sqlite` or `:mysql`. Create the table once:

        postgres: create table atlas_webhook_seen (key text primary key, expires_at timestamptz not null);
        sqlite:   create table atlas_webhook_seen (key text primary key, expires_at integer not null);  -- epoch ms
        mysql:    create table atlas_webhook_seen (`key` varchar(255) primary key, expires_at datetime not null);

    A key whose row has expired counts as unseen and is claimed again; claiming is one atomic statement.
    """
    @behaviour AtlasAuth.WebhookDedupe

    @impl true
    def set_if_absent(%{repo: repo} = ref, key, ttl_seconds) do
      query(repo, Map.get(ref, :dialect, :postgres), key, ttl_seconds)
    end

    @impl true
    def delete(%{repo: repo} = ref, key) do
      sql =
        case Map.get(ref, :dialect, :postgres) do
          :postgres -> "delete from atlas_webhook_seen where key = $1"
          :mysql -> "delete from atlas_webhook_seen where `key` = ?"
          :sqlite -> "delete from atlas_webhook_seen where key = ?"
        end

      {:ok, _} = Ecto.Adapters.SQL.query(repo, sql, [key])
      :ok
    end

    defp query(repo, :sqlite, key, ttl) do
      now = System.system_time(:millisecond)

      {:ok, res} =
        Ecto.Adapters.SQL.query(
          repo,
          "insert into atlas_webhook_seen (key, expires_at) values (?, ?) " <>
            "on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= ? returning key",
          [key, now + ttl * 1000, now]
        )

      res.rows != []
    end

    defp query(repo, :mysql, key, ttl) do
      {:ok, _} = Ecto.Adapters.SQL.query(repo, "delete from atlas_webhook_seen where `key` = ? and expires_at <= now()", [key])

      {:ok, res} =
        Ecto.Adapters.SQL.query(repo, "insert ignore into atlas_webhook_seen (`key`, expires_at) values (?, now() + interval ? second)", [key, trunc(ttl)])

      res.num_rows > 0
    end

    defp query(repo, :postgres, key, ttl) do
      {:ok, res} =
        Ecto.Adapters.SQL.query(
          repo,
          "insert into atlas_webhook_seen (key, expires_at) values ($1, now() + ($2 || ' seconds')::interval) " <>
            "on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= now() returning key",
          [key, to_string(ttl)]
        )

      res.rows != []
    end
  end
end
