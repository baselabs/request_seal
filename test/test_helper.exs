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

# Waits on other processes use one limit sized for a shared, loaded build
# machine; ExUnit's 100 ms default is a scheduling assumption, not a contract.
# A longer limit only delays a real failure. refute_receive keeps its own.
ExUnit.start(exclude: exclude, assert_receive_timeout: 5_000)
Code.require_file("support/multi_signature_helper.exs", __DIR__)
