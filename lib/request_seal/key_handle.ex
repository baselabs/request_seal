defmodule RequestSeal.KeyHandle do
  @moduledoc """
  Caller-owned, algorithm-bound signing, verification, wrapping, unwrapping, derivation, or framed MAC capability.

  Construct handles through a custodian such as `RequestSeal.Custody.Local` or
  `RequestSeal.Custody.SSHAgent`. Only that custodian interprets `ref`, which is
  implementation state outside the major-version compatibility promise: use the
  `RequestSeal.Custody` functions, never the field. Local
  references contain only a holder PID and token, never key material. The holder
  is sensitive and lives until `RequestSeal.Custody.Local.release/1` or creator exit,
  including after handle transfer. Dropping a handle does not stop its holder.
  A long-lived owner such as a GenServer must release handles it no longer needs,
  or create handles once at startup and reuse them for its lifetime.
  `RequestSeal.Custody.Local.Owner` supplies a caller-supervised owner for
  explicitly encoded Ed25519 sources. Fetch a fresh handle for each operation,
  or fetch again and retry once on `:key_not_found` after owner restart.

  Derivation parents bind `{:derive, "hkdf-sha256"}` and grant only `:derive`.
  Their custodian must implement `derive/3`, `commit/3`, and `release/2` together;
  construction refuses an incomplete set. Generated and derived handles contain
  no raw key material. Committed children belong to the original deriving caller,
  independent of the parent. Cleanup obligations use `RequestSeal.Custody.Cleanup`,
  which is not a key handle.

  A handle returned by a JWE resolver is bounded to 4,096 words and 16,384
  binary bytes, including a function's environment and each shared occurrence.
  The resolver process validates this before forwarding the handle. An oversized
  answer gives that item's `:key_resolver_failed`. Store larger custodian state
  behind a reference rather than capturing it in the handle.

  `issued_for` is a caller-chosen purpose atom or nil. The
  `operation_family` distinguishes HTTP signatures, JWS, JWE and derivation.
  Built-in custodians retain the binding independently of the handle.
  Loading the library starts no process or store. Local construction starts one
  holder per handle. An asymmetric public key is obtained through
  `RequestSeal.Custody.public_key/1`; HMAC has no public export.
  """
  @derive {Inspect, only: [:custodian, :algorithm, :capabilities]}
  defstruct [:custodian, :algorithm, :capabilities, :ref, :issued_for, :operation_family]

  @type t :: %__MODULE__{
          custodian: module(),
          algorithm: RequestSeal.Custody.algorithm(),
          capabilities: [RequestSeal.Custody.capability()],
          ref: (-> term()),
          issued_for: atom() | nil,
          operation_family: family() | nil
        }

  @type family :: :http | :jws | :jwe | :derive

  @doc false
  def family({family, _}) when family in [:jws, :jwe, :derive], do: family
  def family(_), do: :http

  @doc false
  def purpose?(value), do: is_atom(value) and not is_boolean(value)

  # Shared construction gate for custodians; opaque references keep the existing
  # zero-arity reference contract, including derivation child references.
  @doc false
  def new(custodian, algorithm, capabilities, ref, issued_for \\ nil) do
    RequestSeal.Custody.Support.safe(fn ->
      if :derive in capabilities do
        RequestSeal.Custody.Support.ensure(
          Code.ensure_loaded?(custodian) and
            Enum.all?([derive: 3, commit: 3, release: 2], fn {name, arity} ->
              function_exported?(custodian, name, arity)
            end),
          :invalid_options
        )
      end

      {:ok,
       %__MODULE__{
         custodian: custodian,
         algorithm: algorithm,
         capabilities: capabilities,
         issued_for: issued_for,
         operation_family: family(algorithm),
         ref: ref
       }}
    end)
  end
end
