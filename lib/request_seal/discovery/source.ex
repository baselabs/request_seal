defmodule RequestSeal.Discovery.Source do
  @moduledoc """
  Caller-configured discovery trust root. `new/1` requires `:type` (`:directory`,
  `:jwks_uri`, or `:cimd`) and `:location` (HTTPS URL, at most 2,048 bytes).
  A directory origin expands to `/.well-known/http-message-signatures-directory`.
  CIMD requires a nonempty path; URLs reject userinfo, fragments and dot segments.
  For CIMD, pass `:location` with exactly the spelling of the document's
  `client_id`, including scheme/host case, any trailing host dot and explicit
  port. The client ID comparison is exact; origin normalization for fetching
  and same-origin checks never changes that comparison.

  Options: `:key_id` (`:thumbprint`, default, or explicit `:directory`).
  Thumbprint mode requires any supplied JWK `kid` to equal its RFC thumbprint.
  Directory mode requires a unique `kid` per JWK (1..256 printable ASCII bytes),
  preserves its spelling, and keeps thumbprints as the revocation identity.
  Directory proof sources (`type: :directory`) require thumbprint mode; their
  signed proof identifies its verification key by thumbprint. Duplicate IDs
  reject among eligible entries only; expired, not-yet-valid, revoked, or
  incompatible entries do not reserve an ID during rotation.
  `:cacerts` (`:os` or DER roots, default `:os`),
  `:permitted_addresses` (at most 16 exact IP tuples, default none),
  `:revoked` (at most 256 RFC thumbprints), `:require_signed_directory` (true),
  `:max_redirects` (0, at most 3), `:redirect_scope` (`:same_origin`, or explicit
  `:any_https`), `:max_bytes` (65,536, at most 1,048,576),
  `:max_decoded_bytes` (65,536, same bound), `:max_keys` (32, at most 256),
  `:timeout` (5,000 milliseconds, 1–300,000), `:min_ttl` (300 seconds),
  `:max_ttl` (86,400 seconds, at most 604,800), `:negative_ttl` (30 seconds,
  at most 300). `min_ttl` supplies fallback freshness only when neither `max-age`
  nor `Expires` is present; it never extends explicit freshness or a key/signature
  expiry. Invalid `negative_ttl` returns `:invalid_options`.
  CIMD response content additionally has a 5,120-byte cap.

  Unknown keys reject. Modified structs are revalidated at every fetch. Inspection
  excludes locations, addresses, trust roots and revoked IDs. No networking occurs
  during construction. Starting SSL remains the caller's responsibility.
  """
  alias RequestSeal.Discovery.{Address, Support, Error}
  import Support, only: [ensure: 2]
  @derive {Inspect, only: [:type]}
  defstruct [
    :type,
    :location,
    key_id: :thumbprint,
    cacerts: :os,
    permitted_addresses: [],
    revoked: [],
    require_signed_directory: true,
    max_redirects: 0,
    redirect_scope: :same_origin,
    max_bytes: 65_536,
    max_decoded_bytes: 65_536,
    max_keys: 32,
    timeout: 5_000,
    min_ttl: 300,
    max_ttl: 86_400,
    negative_ttl: 30
  ]

  @type t :: %__MODULE__{
          type: :directory | :jwks_uri | :cimd,
          location: binary(),
          key_id: :thumbprint | :directory,
          cacerts: :os | [binary()],
          permitted_addresses: [tuple()],
          revoked: [binary()],
          require_signed_directory: boolean(),
          max_redirects: non_neg_integer(),
          redirect_scope: :same_origin | :any_https,
          max_bytes: pos_integer(),
          max_decoded_bytes: pos_integer(),
          max_keys: pos_integer(),
          timeout: pos_integer(),
          min_ttl: non_neg_integer(),
          max_ttl: non_neg_integer(),
          negative_ttl: non_neg_integer()
        }
  @directory "/.well-known/http-message-signatures-directory"
  @doc "Construct a bounded explicit source; malformed inputs return :invalid_source."
  @spec new(map()) :: {:ok, t()} | {:error, Error.t()}
  def new(attrs) do
    Support.safe(
      fn ->
        ensure(is_map(attrs) and not is_struct(attrs), :invalid_source)

        ensure(
          Enum.all?(Map.keys(attrs), &(&1 in Map.keys(Map.from_struct(%__MODULE__{})))),
          :invalid_source
        )

        s = struct(__MODULE__, attrs)
        ensure(s.type in [:directory, :jwks_uri, :cimd], :invalid_source)
        uri = url!(s.location)
        ensure(s.type != :cimd or uri.path not in [nil, ""], :invalid_source)

        location =
          if s.type == :directory and uri.path in [nil, "", "/"],
            do: origin(uri) <> @directory,
            else: s.location

        ensure(
          s.type != :directory or (URI.parse(location).path == @directory and uri.query == nil),
          :invalid_source
        )

        ensure(s.key_id in [:thumbprint, :directory], :invalid_source)
        ensure(s.type != :directory or s.key_id == :thumbprint, :invalid_source)
        ensure(is_boolean(s.require_signed_directory), :invalid_source)

        for {n, lo, hi} <- [
              {s.max_redirects, 0, 3},
              {s.max_bytes, 1, 1_048_576},
              {s.max_decoded_bytes, 1, 1_048_576},
              {s.max_keys, 1, 256},
              {s.timeout, 1, 300_000},
              {s.min_ttl, 0, 604_800},
              {s.max_ttl, 0, 604_800}
            ] do
          ensure(is_integer(n) and n in lo..hi, :invalid_source)
        end

        ensure(is_integer(s.negative_ttl) and s.negative_ttl in 0..300, :invalid_options)

        ensure(
          s.min_ttl <= s.max_ttl and s.redirect_scope in [:same_origin, :any_https],
          :invalid_source
        )

        ensure(
          is_list(s.permitted_addresses) and length(s.permitted_addresses) <= 16 and
            Enum.all?(s.permitted_addresses, &Address.valid?/1),
          :invalid_source
        )

        ensure(
          is_list(s.revoked) and length(s.revoked) <= 256 and Enum.all?(s.revoked, &thumbprint?/1),
          :invalid_source
        )

        ensure(
          s.cacerts == :os or
            (is_list(s.cacerts) and s.cacerts != [] and Enum.all?(s.cacerts, &certificate?/1)),
          :invalid_source
        )

        {:ok, %{s | location: location}}
      end,
      :invalid_source
    )
  end

  defp certificate?(der) when is_binary(der) and byte_size(der) in 1..16_384 do
    :public_key.pkix_decode_cert(der, :otp)
    true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp certificate?(_), do: false

  @doc false
  def validate!(%__MODULE__{} = source) do
    case new(Map.from_struct(source)) do
      {:ok, ^source} -> source
      {:error, %Error{reason: reason}} -> ensure(false, reason)
      _ -> ensure(false, :invalid_source)
    end
  end

  def validate!(_), do: ensure(false, :invalid_source)
  @doc false
  def thumbprint?(value) do
    is_binary(value) and byte_size(value) == 43 and
      case Base.url_decode64(value, padding: false) do
        {:ok, bytes} ->
          byte_size(bytes) == 32 and Base.url_encode64(bytes, padding: false) == value

        _ ->
          false
      end
  end

  @doc false
  def key_id?(%__MODULE__{key_id: :thumbprint}, value), do: thumbprint?(value)
  def key_id?(%__MODULE__{key_id: :directory}, value), do: directory_id?(value)
  def key_id?(_, _), do: false

  @doc "Accept directory key IDs containing 1–256 printable ASCII bytes, preserving spelling."
  @spec directory_id?(term()) :: boolean()
  def directory_id?(value),
    do:
      is_binary(value) and byte_size(value) in 1..256 and
        Regex.match?(~r/\A[\x20-\x7e]+\z/, value)

  @doc false
  def url!(location) do
    ensure(
      is_binary(location) and byte_size(location) in 1..2048 and
        Regex.match?(~r/\A[\x21-\x7e]+\z/, location),
      :invalid_source
    )

    uri = URI.parse(location)

    ensure(
      uri.scheme == "https" and is_binary(uri.host) and uri.host != "" and uri.userinfo == nil and
        uri.fragment == nil and uri.port in 1..65_535,
      :invalid_source
    )

    ensure(
      Regex.match?(~r/\A(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?\z/, uri.authority),
      :invalid_source
    )

    ensure(
      not String.contains?(location, "\\") and not Regex.match?(~r/%(?![a-fA-F0-9]{2})/, location),
      :invalid_source
    )

    ensure(
      Enum.all?(String.split(uri.path || "", "/"), &(URI.decode(&1) not in [".", ".."])),
      :invalid_source
    )

    ensure(not String.contains?(URI.decode(uri.path || ""), ["\r", "\n", "\\"]), :invalid_source)
    uri
  end

  @doc false
  def authority(uri), do: uri |> origin() |> URI.parse() |> origin_authority()

  defp origin_authority(uri) do
    host = if String.contains?(uri.host, ":"), do: "[" <> uri.host <> "]", else: uri.host
    host <> if(uri.port == 443, do: "", else: ":" <> Integer.to_string(uri.port))
  end

  @doc false
  def origin(uri) do
    host = uri.host |> String.downcase() |> String.replace_suffix(".", "")
    String.downcase(uri.scheme) <> "://" <> origin_authority(%{uri | host: host})
  end
end
