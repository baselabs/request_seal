exclude =
  if System.get_env("REQUESTSEAL_REPLAY_PG_URL"),
    do: [:live_source],
    else: [:live_source, :postgres]

exclude =
  if System.get_env("REQUESTSEAL_REPLAY_PG_URL") &&
       System.get_env("REQUESTSEAL_REPLAY_PG_RESTART_CMD"),
     do: exclude,
     else: [:postgres_restart | exclude]

exclude =
  if Code.ensure_loaded?(AshOnetime.Transaction),
    do: exclude,
    else: [:owned_integrations | exclude]

ExUnit.start(exclude: exclude)
Code.require_file("support/multi_signature_helper.exs", __DIR__)
