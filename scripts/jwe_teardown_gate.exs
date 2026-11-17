# The Python entry owns the command and its artifact. This file runs only in CI.
[output] = System.argv()
report = RequestSeal.Test.JWETeardownGate.run()
File.write!(output, :json.encode(report) |> IO.iodata_to_binary())
if report.derived_k_pf_us > RequestSeal.JOSE.JWE.Bounds.preflight() or
     Enum.any?(report.scenarios, &(Enum.max(&1.times_us) > 170_000)) do
  System.halt(1)
end
