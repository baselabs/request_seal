if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Scope do
    @moduledoc """
    Binds tenant context to a covered request path after successful verification.

    Place this plug after Capture, any configured body parsers, and Verify.
    Use the returned tenant as context for the data layer's own authorization.
    """

    @behaviour Plug
    alias RequestSeal.Adapter.Error
    alias RequestSeal.Custody
    alias RequestSeal.Custody.Context
    alias RequestSeal.Plug.{Delivery, State}

    @enforce_keys [:template, :tenant, :principal_tenant, :on_reject]
    @derive {Inspect, only: [:validator]}
    defstruct [
      :template,
      :tenant,
      :principal_tenant,
      :on_reject,
      validator: :token,
      lookup_timeout: 1_000,
      refuse_names: ["tenant", "tenant_id"],
      refuse_headers: ["x-tenant", "x-tenant-id"]
    ]

    @type t :: %__MODULE__{}
    @type result :: %{tenant: binary(), captures: %{binary() => binary()}}
    @type ash_binding :: %{
            actor: (term() -> {:ok, term()} | :error),
            unattributed: :anonymous | :reject
          }

    @required [:template, :tenant, :principal_tenant, :on_reject]
    @keys @required ++ [:validator, :lookup_timeout, :refuse_names, :refuse_headers]
    @literal ~r/\A[A-Za-z0-9._~-]{1,128}\z/
    @token ~r/\A[a-z0-9_-]{1,128}\z/
    @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

    @doc """
    Compiles a template and a trusted principal-to-tenant function.

    Required options are `:template` (such as `"/teams/:tenant/*"`), `:tenant`
    (the capture name as a string or atom), `:principal_tenant` (an arity-one
    function returning `{:ok, tenant}` for a verification's principal), and
    `:on_reject` (`:continue` or `{:halt, status}`).

    Literal segments use URI unreserved characters. Capture names are unique
    lowercase names with digits and underscores. A final `*` permits additional
    safe segments. The optional `:validator` is `:token` by default or `:uuid`
    for lowercase UUID text. Token captures also use lowercase ASCII.
    `:lookup_timeout` bounds principal mapping in milliseconds (1–30,000,
    default 1,000). Optional `:refuse_names` and `:refuse_headers` add
    competing selectors to the defaults. Malformed options return
    `{:error, %RequestSeal.Adapter.Error{reason: :invalid_options}}`.
    """
    @spec new(map() | keyword()) :: {:ok, t()} | {:error, Error.t()}
    def new(attrs) when is_list(attrs) do
      if Keyword.keyword?(attrs) and length(attrs) == map_size(Map.new(attrs)),
        do: new(Map.new(attrs)),
        else: reject(:invalid_options)
    end

    def new(attrs) when is_map(attrs) do
      with true <- Enum.all?(Map.keys(attrs), &(&1 in @keys)),
           true <- Enum.all?(@required, &Map.has_key?(attrs, &1)),
           opts = struct!(__MODULE__, attrs),
           {:ok, template} <- compile(opts.template),
           tenant = capture_name(opts.tenant),
           true <- {:capture, tenant} in template,
           true <- is_function(opts.principal_tenant, 1),
           true <- valid_rejection?(opts.on_reject),
           true <- opts.validator in [:token, :uuid],
           true <- is_integer(opts.lookup_timeout) and opts.lookup_timeout in 1..30_000,
           true <- names?(opts.refuse_names),
           true <- names?(opts.refuse_headers) and Enum.all?(opts.refuse_headers, &header?/1) do
        {:ok,
         %{
           opts
           | template: template,
             tenant: tenant,
             refuse_names: Enum.uniq(["tenant", "tenant_id", tenant | opts.refuse_names]),
             refuse_headers: Enum.uniq(["x-tenant", "x-tenant-id" | opts.refuse_headers])
         }}
      else
        _ -> reject(:invalid_options)
      end
    end

    def new(_), do: reject(:invalid_options)

    @doc "Compiles options for a Plug pipeline, raising an adapter error on invalid options."
    @impl Plug
    @spec init(map() | keyword() | t()) :: t()
    def init(%__MODULE__{} = options), do: options

    def init(options) do
      case new(options) do
        {:ok, options} -> options
        {:error, error} -> raise error
      end
    end

    @doc """
    Binds scope once using the captured path and the verified signature coverage.

    Nonempty bodies must have been fully read from Capture's retained adapter
    and parsed into a map by a configured parser. Competing headers refuse
    in both the captured and current headers. Nested maps and lists are
    inspected for selectors, including query names discarded during decoding.
    Unfetched and opaque nested values refuse,
    except for uploads. Percent escapes and empty or dot segments refuse
    before any capture is bound.

    Refusals are stored as bounded adapter errors at stage `:scope`. With
    `{:halt, status}` the plug sends an empty response and halts. Read an accepted
    binding through `RequestSeal.Plug.scope/1`.
    """
    @impl Plug
    @spec call(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def call(conn, options) do
      state = State.get(conn)

      result =
        if state.scope == nil,
          do: bind(conn, state, options),
          else: reject(:already_scoped)

      conn = State.put(conn, %{state | scope: result})

      case {result, options.on_reject} do
        {{:error, _}, {:halt, status}} ->
          conn |> Plug.Conn.halt() |> Plug.Conn.send_resp(status, "")

        _ ->
          conn
      end
    end

    @doc """
    Maps an accepted binding into an Ash scope using the captured tenant.

    Pass the usual actor and unattributed choices. A tenant supplied separately
    in the binding returns `:invalid_binding`; a connection without an accepted
    scope returns `:scope_unbound`. Ash still authorizes the data operation.
    """
    @spec ash_scope(Plug.Conn.t(), ash_binding()) ::
            {:ok, RequestSeal.Ash.Scope.t()} | {:error, RequestSeal.Error.t()}
    def ash_scope(conn, binding) do
      with true <- is_map(binding) and not Map.has_key?(binding, :tenant),
           {:ok, verification} <- RequestSeal.Plug.verification(conn),
           {:ok, %{tenant: tenant}} <- RequestSeal.Plug.scope(conn) do
        RequestSeal.Ash.scope(verification, Map.put(binding, :tenant, {:value, tenant}))
      else
        false -> {:error, RequestSeal.Error.new(:invalid_binding, :binding)}
        :error -> {:error, RequestSeal.Error.new(:scope_unbound, :binding)}
      end
    end

    defp bind(conn, %{verification: {:ok, %RequestSeal.Verification{} = verification}} = state, opts) do
      with :ok <- covered(verification),
           {:ok, path, query} <- target(state),
           {:ok, segments} <- segments(path, conn),
           {:ok, captures} <- match_template(opts.template, segments, %{}),
           :ok <- validate(captures, opts.validator),
           :ok <- refuse_header(conn, state.capture.message.fields, opts.refuse_headers),
           :ok <- refuse_query(conn, query, opts.refuse_names),
           :ok <- refuse_body(conn, state.capture.message.body.bytes, opts.refuse_names),
           tenant = Map.fetch!(captures, opts.tenant),
           :ok <- agree(opts, verification.principal, tenant) do
        {:ok, %{tenant: tenant, captures: captures}}
      end
    end

    defp bind(_, _, _), do: reject(:unverified)

    defp covered(%{signature: %{covered: components, crypto: :valid}}) do
      if ~s("@path") in components, do: :ok, else: reject(:path_not_covered)
    end

    defp target(%{capture: %{message: %{raw_target: "/" <> _ = target}}}) do
      case :binary.split(target, "?") do
        [path, query] -> {:ok, path, query}
        [path] -> {:ok, path, ""}
      end
    end

    defp target(_), do: reject(:path_rewritten)

    defp segments("/" <> path, conn) do
      raw = :binary.split(path, "/", [:global])

      cond do
        not Enum.all?(raw, &safe_segment?/1) -> reject(:ambiguous_path)
        raw != conn.script_name ++ conn.path_info -> reject(:path_rewritten)
        true -> {:ok, raw}
      end
    end

    defp safe_segment?(value), do: value not in [".", ".."] and Regex.match?(@literal, value)

    defp match_template([], [], captures), do: {:ok, captures}
    defp match_template([:tail], _, captures), do: {:ok, captures}

    defp match_template([{:literal, value} | rest], [value | path], captures),
      do: match_template(rest, path, captures)

    defp match_template([{:capture, name} | rest], [value | path], captures),
      do: match_template(rest, path, Map.put(captures, name, value))

    defp match_template(_, _, _), do: reject(:template_mismatch)

    defp validate(captures, validator) do
      regex = if validator == :uuid, do: @uuid, else: @token

      if Enum.all?(captures, fn {_, value} -> Regex.match?(regex, value) end),
        do: :ok,
        else: reject(:invalid_scope)
    end

    defp refuse_header(conn, captured, names) do
      header? = fn name -> String.downcase(name) in names end

      if Enum.any?(captured, &header?.(&1.name)) or
           Enum.any?(conn.req_headers, fn {name, _} -> header?.(name) end) do
        reject(:scope_in_header)
      else
        :ok
      end
    end

    defp refuse_query(conn, query, names) when query == conn.query_string do
      fresh = %{conn | query_params: %Plug.Conn.Unfetched{aspect: :query_params}}
      _ = Plug.Conn.fetch_query_params(fresh)

      result =
        if raw_query_selector?(query, names),
          do: :selector,
          else: inspect_optional(conn.query_params, names)

      case result do
        :selector -> reject(:scope_in_query)
        :indeterminate -> reject(:invalid_query)
        :clean -> :ok
      end
    rescue
      _ in [Plug.Conn.InvalidQueryError] -> reject(:invalid_query)
    end

    defp refuse_query(_, _, _), do: reject(:invalid_query)

    # Decode each name separately with Plug's bracket rules so merging
    # repeated parents or finalizing lists cannot erase a selector.
    defp raw_query_selector?(query, names) do
      query
      |> :binary.split("&", [:global])
      |> Enum.any?(fn pair ->
        [name | _] = :binary.split(pair, "=")
        inspect_params(Plug.Conn.Query.decode(name), names) == :selector
      end)
    end

    defp refuse_body(conn, bytes, names) do
      params = conn.body_params

      if bytes != "" and
           (is_struct(params) or not is_map(params) or
              not Delivery.replayed?(conn.adapter) or
              not Delivery.replay_matches?(conn.adapter, bytes)) do
        reject(:body_uninspected)
      else
        case inspect_optional(params, names) do
          :selector -> reject(:scope_in_body)
          :indeterminate -> reject(:body_uninspected)
          :clean -> :ok
        end
      end
    end

    # The raw query was parsed separately, and a nonempty body is required
    # to have top-level parse evidence before reaching this check.
    defp inspect_optional(%Plug.Conn.Unfetched{}, _), do: :clean
    defp inspect_optional(params, names), do: inspect_params(params, names)

    defp inspect_params(%Plug.Upload{}, _), do: :clean
    defp inspect_params(params, _) when is_struct(params), do: :indeterminate

    defp inspect_params(params, names) when is_map(params) do
      Enum.reduce_while(params, :clean, fn {key, value}, status ->
        name = if is_atom(key), do: Atom.to_string(key), else: key

        if name in names do
          {:halt, :selector}
        else
          case combine(status, inspect_params(value, names)) do
            :selector -> {:halt, :selector}
            result -> {:cont, result}
          end
        end
      end)
    end

    defp inspect_params([], _), do: :clean
    defp inspect_params([_ | _] = params, names), do: inspect_list(params, names, :clean)

    defp inspect_params(value, _) when is_binary(value) or is_number(value) or is_atom(value),
      do: :clean

    defp inspect_params(_, _), do: :indeterminate

    defp inspect_list([], _, status), do: status

    defp inspect_list([head | tail], names, status) do
      case combine(status, inspect_params(head, names)) do
        :selector -> :selector
        result -> inspect_list(tail, names, result)
      end
    end

    defp inspect_list(_, _, _), do: :indeterminate

    defp combine(:selector, _), do: :selector
    defp combine(_, :selector), do: :selector
    defp combine(:indeterminate, _), do: :indeterminate
    defp combine(:clean, result), do: result

    defp agree(opts, principal, tenant) do
      context = %Context{
        owner: self(),
        deadline: System.monotonic_time(:millisecond) + opts.lookup_timeout
      }

      case Custody.run(context, fn -> {:ok, opts.principal_tenant.(principal)} end) do
        {:ok, {:ok, ^tenant}} -> :ok
        {:error, %{reason: :deadline_exceeded}} -> reject(:tenant_lookup_timeout)
        _ -> reject(:tenant_mismatch)
      end
    end

    defp compile("/" <> path) when byte_size(path) in 1..2048 do
      parts = :binary.split(path, "/", [:global])
      reversed = Enum.reverse(parts)

      template =
        case reversed do
          ["*" | prefix] -> Enum.reverse([:tail | Enum.map(prefix, &segment/1)])
          _ -> Enum.map(parts, &segment/1)
        end

      captures = for {:capture, name} <- template, do: name

      if length(parts) <= 64 and :invalid not in template and captures == Enum.uniq(captures),
        do: {:ok, template},
        else: :error
    end

    defp compile(_), do: :error

    defp segment(":" <> name) do
      if Regex.match?(~r/\A[a-z][a-z0-9_]{0,31}\z/, name),
        do: {:capture, name},
        else: :invalid
    end

    defp segment(value) do
      if safe_segment?(value), do: {:literal, value}, else: :invalid
    end

    defp capture_name(value) when is_atom(value), do: Atom.to_string(value)
    defp capture_name(value), do: value

    defp names?(names) when is_list(names) and length(names) <= 64,
      do: Enum.all?(names, &(is_binary(&1) and byte_size(&1) in 1..256))

    defp names?(_), do: false

    defp header?(value),
      do: Regex.match?(~r/\A[!#$%&'*+.^_`|~0-9a-z-]+\z/, value)

    defp valid_rejection?(:continue), do: true
    defp valid_rejection?({:halt, status}), do: is_integer(status) and status in 200..599
    defp valid_rejection?(_), do: false

    defp reject(reason), do: {:error, Error.new(reason, :plug, :scope, 0)}
  end
end
