defmodule RequestSeal.Adapter.Signing do
  @moduledoc false
  @type spec :: RequestSeal.Signing.spec()
  defdelegate protect(adapter, stage, attempt, fun), to: RequestSeal.Signing
  defdelegate ensure(value, reason), to: RequestSeal.Signing
  def fail(reason, source \\ nil), do: RequestSeal.Signing.fail(reason, source)
  defdelegate options(opts, allowed), to: RequestSeal.Signing
  defdelegate normalize_spec!(spec), to: RequestSeal.Signing
  def spec!(spec, opts \\ []), do: RequestSeal.Signing.spec!(spec, opts)
  defdelegate sign_options!(opts), to: RequestSeal.Signing
  defdelegate body_option!(option), to: RequestSeal.Signing
  defdelegate body(body, option), to: RequestSeal.Signing
  defdelegate retained(bytes), to: RequestSeal.Signing
  defdelegate body_required?(input, spec), to: RequestSeal.Signing
  defdelegate covered?(input, name), to: RequestSeal.Signing

  def sign(message, spec, signer, opts, mode \\ []),
    do: RequestSeal.Signing.sign(message, spec, signer, opts, mode)

  defdelegate field(name, value), to: RequestSeal.Signing
end
