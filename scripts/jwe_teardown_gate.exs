# The Python entry owns the command and its artifact. This file runs only in CI.
[output] = System.argv()
report = try do
  RequestSeal.Test.JWETeardownGate.run()
rescue
  error ->
    %{error: Exception.format(:error, error, __STACKTRACE__),
      host: RequestSeal.Test.JWETeardownGate.host()}
end
File.write!(output, :json.encode(report) |> IO.iodata_to_binary())
if Map.has_key?(report, :error) or
     report.derived_k_pf_us > report.constants.k_pf_us or
     Enum.any?(report.scenarios, &(Enum.max(&1.times_us) > report.constants.b_us)) do
  System.halt(1)
end
