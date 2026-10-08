import Config

# Keep this assertion, .tool-versions, mix.exs, and CI in lockstep.
expected_otp = "29"
running_otp = to_string(:erlang.system_info(:otp_release))

if running_otp != expected_otp do
  raise "RequestSeal requires Erlang/OTP #{expected_otp}; running #{running_otp} (Elixir #{System.version()})."
end

if config_env() == :test do
  config :ash, default_string_length_count: :codepoints
end
