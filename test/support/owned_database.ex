if Code.ensure_loaded?(AshOnetime.Transaction) do
  defmodule RequestSeal.OwnedRepo do
    @moduledoc false
    use AshPostgres.Repo, otp_app: :request_seal, warn_on_missing_ash_functions?: false
    def min_pg_version, do: %Version{major: 16, minor: 0, patch: 0}
  end

  defmodule RequestSeal.OwnedDatabase do
    @moduledoc false
    import ExUnit.Callbacks
    alias RequestSeal.OwnedRepo, as: Repo

    def start do
      start_supervised!(
        {Repo,
         url: System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"),
         pool_size: 16,
         queue_target: 1_000,
         log: false}
      )

      schema = "requestseal_owned_#{System.unique_integer([:positive])}"
      Repo.query!("CREATE SCHEMA #{schema}")
      # Use the package's documented migration generator, then Ecto's migrator.
      migration = RequestSeal.OwnedRepo.Migrations.InstallAshOnetime

      unless Code.ensure_loaded?(migration) do
        source = Mix.Tasks.AshOnetime.Gen.Migrations.render(Repo, [])
        Code.compile_string(source)
      end

      Ecto.Migrator.up(Repo, 1, migration, prefix: schema, log: false)
      schema
    end

    def drop(schema) do
      {:ok, connection} =
        Postgrex.start_link(
          Ecto.Repo.Supervisor.parse_url(System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"))
        )

      try do
        Postgrex.query!(connection, "DROP SCHEMA #{schema} CASCADE", [])
      after
        GenServer.stop(connection)
      end
    end
  end
end
