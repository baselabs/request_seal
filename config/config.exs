import Config

# OTP 27 introduced :json, used by discovery and JOSE.
minimum_otp = 27
running_otp = :erlang.system_info(:otp_release) |> to_string() |> String.to_integer()

if running_otp < minimum_otp do
  raise "RequestSeal requires Erlang/OTP #{minimum_otp} or newer for :json; running #{running_otp} (Elixir #{System.version()})."
end

if config_env() == :test do
  config :ash, default_string_length_count: :codepoints
end
