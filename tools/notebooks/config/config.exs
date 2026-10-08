import Config
import_config "../../../config/config.exs"

# Notebook tooling keeps the exact development identity, unlike the library.
expected_otp = "29"
running_otp = to_string(:erlang.system_info(:otp_release))

if running_otp != expected_otp do
  raise "Notebook tooling requires Erlang/OTP #{expected_otp}; running #{running_otp}."
end

# Required compile-time configuration for Livebook as a library dependency.
# The notebook runner uses --no-start; no endpoint or application is started.
config :livebook, LivebookWeb.Endpoint, server: false, live_reload: []
config :livebook, Livebook.Apps.Manager, retry_backoff_base_ms: 5_000

config :livebook,
  feature_flags: [],
  learn_notebooks: [],
  k8s_kubeconfig_pipeline: Kubereq.Kubeconfig.Default

config :phoenix, :json_library, JSON
