defmodule RequestSeal.Crypto.Error do
  @moduledoc """
  Bounded primitive and public-key errors, containing no supplied material.

  Reasons: `:unsupported_algorithm`, `:unsupported_format`, `:invalid_key`,
  `:key_mismatch`, `:invalid_options`, `:invalid_data`, and `:invalid_signature`. Correct the input
  before retrying. These facts do not establish authentication or authorization.
  """
  @enforce_keys [:reason]
  defstruct [:reason]

  @type reason ::
          :invalid_data
          | :invalid_key
          | :invalid_options
          | :invalid_signature
          | :key_mismatch
          | :unsupported_algorithm
          | :unsupported_format
  @type t :: %__MODULE__{reason: reason()}
end
