defmodule RequestSeal.KeyIdentity do
  @moduledoc """
  Internal trusted key equivalence, redacted from default inspection.

  Public identities use validated `RequestSeal.PublicKey` components, with
  `:rsa_pss` normalized to `:rsa`. Symmetric identities are opaque, nonsecret
  custodian-supplied binaries of 1–256 bytes. RequestSeal never derives one from
  a secret. A caller must supply the same identity for aliases within its trusted
  scope. Unknown equivalence never establishes equality, including with itself.
  Do not place these internal values in general results, logs, or telemetry.
  """
  @derive {Inspect, only: [:kind]}
  defstruct [:kind, :value]
  @type t :: %__MODULE__{kind: :public | :symmetric | :unknown, value: term()}

  @doc "Compare known, validated identities; unknown or malformed identities never match."
  @spec same?(t(), t()) :: boolean()
  def same?(%__MODULE__{kind: :public, value: a}, %__MODULE__{kind: :public, value: b}) do
    case {RequestSeal.PublicKey.import(a, :raw), RequestSeal.PublicKey.import(b, :raw)} do
      {{:ok, _}, {:ok, _}} -> normalize(a) == normalize(b)
      _ -> false
    end
  end

  def same?(%__MODULE__{kind: :symmetric, value: a}, %__MODULE__{kind: :symmetric, value: b})
      when is_binary(a) and byte_size(a) in 1..256 and is_binary(b) and byte_size(b) in 1..256,
      do: a == b

  def same?(_, _), do: false

  @doc false
  def normalize({:rsa_pss, n, e}), do: {:rsa, n, e}
  def normalize(material), do: material
end
