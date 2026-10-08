exclude =
  if System.get_env("REQUESTSEAL_REPLAY_PG_URL"),
    do: [:live_source],
    else: [:live_source, :postgres]

exclude =
  if System.get_env("REQUESTSEAL_REPLAY_PG_URL") &&
       System.get_env("REQUESTSEAL_REPLAY_PG_RESTART_CMD"),
     do: exclude,
     else: [:postgres_restart | exclude]

ExUnit.start(exclude: exclude)
Code.require_file("support/multi_signature_helper.exs", __DIR__)
