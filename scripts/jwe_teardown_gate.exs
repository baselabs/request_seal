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
     Enum.any?(report.scenarios, fn row ->
       Enum.max(row.times_us) > report.constants.b_us or
         Enum.any?(row.diagnostics, fn sample ->
           sample.remaining != 0 or sample.missing_end_roles != [] or
             sample.live_roles != [] or sample.failures != []
         end)
     end) do
  System.halt(1)
end
