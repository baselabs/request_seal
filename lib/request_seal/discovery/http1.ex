defmodule RequestSeal.Discovery.HTTP1 do
  # SSL is optional: the consuming application declares and starts it.
  @compile {:no_warn_undefined, :ssl}
  @moduledoc false
  alias RequestSeal.{Body, FieldOccurrence, Message, TransportFacts}
  alias RequestSeal.Discovery.{Source, Support}
  import Support, only: [ensure: 2, unwrap: 1]
  @header_cap 16_384

  def request(socket, uri, source, deadline) do
    target =
      if(uri.path in [nil, ""], do: "/", else: uri.path) <>
        if(uri.query == nil, do: "", else: "?" <> uri.query)

    authority = Source.authority(uri)

    accept =
      if source.type == :directory,
        do: "application/http-message-signatures-directory+json",
        else: "application/json, application/jwk-set+json"

    request_fields =
      Enum.map(
        [
          {"Host", authority},
          {"Accept", accept},
          {"Accept-Encoding", "gzip"},
          {"Connection", "close"}
        ],
        fn {name, value} -> field(name <> ": " <> value) end
      )

    case :ssl.send(socket, [
           "GET ",
           target,
           " HTTP/1.1\r\n",
           Enum.map(request_fields, fn f -> [f.name, ":", f.value, "\r\n"] end),
           "\r\n"
         ]) do
      :ok -> :ok
      _ -> ensure(false, :connect_failed)
    end

    state = %{
      socket: socket,
      buffer: "",
      deadline: deadline,
      read: 0,
      wire_cap: source.max_bytes * 16 + @header_cap * 2
    }

    {head, state} = section(state, @header_cap)
    [status | lines] = :binary.split(head, "\r\n", [:global])

    code =
      case Regex.run(~r/\AHTTP\/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?\z/, status) do
        [_, digits] -> String.to_integer(digits)
        _ -> ensure(false, :invalid_response)
      end

    fields = Enum.map(lines, &field/1)
    ensure(code in 100..599, :invalid_response)
    validate_framing(fields)
    # Redirect/error bodies are never needed and never consumed.
    if code != 200 do
      {code, fields, nil, nil}
    else
      {encoded, trailers, _} = body(state, fields, source.max_bytes)

      decoded =
        decode(encoded, value(fields, "content-encoding"), source.max_decoded_bytes, deadline)

      ensure(source.type != :cimd or byte_size(decoded) <= 5120, :limit)
      empty = unwrap(Body.new(%{state: :retained, bytes: ""}))

      body =
        unwrap(Body.new(%{state: :retained, bytes: encoded, max_bytes: source.max_bytes}))

      transport = unwrap(TransportFacts.new(%{}))

      req =
        unwrap(
          Message.new(%{
            kind: :request,
            method: "GET",
            raw_target: target,
            target_form: :origin,
            scheme: "https",
            authority: authority,
            fields: request_fields,
            trailers: [],
            body: empty,
            transport: transport
          })
        )

      message =
        unwrap(
          Message.new(%{
            kind: :response,
            status: code,
            fields: fields,
            trailers: trailers,
            body: body,
            transport: transport,
            related_request: req
          })
        )

      {code, fields, message, decoded}
    end
  end

  def value(fields, name) do
    values = for f <- fields, String.downcase(f.name) == name, do: String.trim(f.value)
    ensure(length(values) <= 1, :invalid_response)
    List.first(values)
  end

  def values(fields, name),
    do: for(f <- fields, String.downcase(f.name) == name, do: String.trim(f.value))

  defp field(line, section \\ :headers) do
    case :binary.split(line, ":") do
      [name, value] ->
        case FieldOccurrence.new(%{
               name: name,
               value: value,
               section: section,
               provenance: :http1
             }) do
          {:ok, f} -> f
          _ -> ensure(false, :invalid_response)
        end

      _ ->
        ensure(false, :invalid_response)
    end
  end

  defp validate_framing(fields) do
    te = value(fields, "transfer-encoding")
    cl = value(fields, "content-length")
    ensure(te == nil or cl == nil, :invalid_response)
    ensure(te == nil or String.downcase(te) == "chunked", :invalid_response)

    if cl != nil,
      do: ensure(byte_size(cl) <= 10 and Regex.match?(~r/\A[0-9]+\z/, cl), :invalid_response)
  end

  defp body(state, fields, cap) do
    case {value(fields, "transfer-encoding"), value(fields, "content-length")} do
      {nil, nil} ->
        close_body(state, [], 0, cap)

      {nil, length} ->
        length = String.to_integer(length)
        ensure(length <= cap, :limit)
        {bytes, state} = take(state, length)
        {bytes, [], state}

      {_, nil} ->
        chunks(state, [], 0, cap)
    end
  end

  defp close_body(state, acc, size, cap) do
    size = size + byte_size(state.buffer)
    ensure(size <= cap, :limit)
    acc = [state.buffer | acc]

    case receive_bytes(%{state | buffer: ""}, true) do
      :closed -> {IO.iodata_to_binary(Enum.reverse(acc)), [], state}
      state -> close_body(state, acc, size, cap)
    end
  end

  defp chunks(state, acc, size, cap) do
    {line, state} = line(state, 1024)
    [digits | extensions] = :binary.split(line, ";", [:global])

    ensure(
      byte_size(digits) in 1..8 and Regex.match?(~r/\A[0-9a-fA-F]+\z/, digits),
      :invalid_response
    )

    ensure(
      Enum.all?(extensions, &(byte_size(&1) > 0 and Regex.match?(~r/\A[\x20-\x7e]+\z/, &1))),
      :invalid_response
    )

    count = String.to_integer(digits, 16)
    ensure(size + count <= cap, :limit)

    if count == 0 do
      {trailers, state} = trailers(state, [], 0)
      {IO.iodata_to_binary(Enum.reverse(acc)), trailers, state}
    else
      {bytes, state} = take(state, count)
      {ending, state} = take(state, 2)
      ensure(ending == "\r\n", :invalid_response)
      chunks(state, [bytes | acc], size + count, cap)
    end
  end

  defp trailers(state, fields, bytes) do
    {line, state} = line(state, @header_cap - bytes)
    bytes = bytes + byte_size(line) + 2
    ensure(bytes <= @header_cap and length(fields) <= 128, :limit)

    if line == "" do
      {Enum.reverse(fields), state}
    else
      f = field(line, :trailers)
      # Framing metadata and authentication fields in trailers cannot alter
      # headers or establish a directory proof.
      ensure(
        String.downcase(f.name) not in ["content-length", "transfer-encoding", "host"],
        :invalid_response
      )

      trailers(state, [f | fields], bytes)
    end
  end

  defp section(state, cap), do: delimited(state, "\r\n\r\n", cap)
  defp line(state, cap), do: delimited(state, "\r\n", cap)

  defp delimited(state, delimiter, cap) do
    case :binary.match(state.buffer, delimiter) do
      {pos, width} ->
        ensure(pos + width <= cap, :limit)
        <<head::binary-size(^pos), _::binary-size(^width), rest::binary>> = state.buffer
        {head, %{state | buffer: rest}}

      :nomatch ->
        ensure(byte_size(state.buffer) < cap, :limit)
        delimited(receive_bytes(state), delimiter, cap)
    end
  end

  defp take(state, n) do
    if byte_size(state.buffer) >= n do
      <<bytes::binary-size(^n), rest::binary>> = state.buffer
      {bytes, %{state | buffer: rest}}
    else
      take(receive_bytes(state), n)
    end
  end

  defp receive_bytes(state, allow_close \\ false) do
    case :ssl.recv(state.socket, 0, Support.remaining(state.deadline)) do
      {:ok, bytes} ->
        read = state.read + byte_size(bytes)
        ensure(read <= state.wire_cap, :limit)
        %{state | buffer: state.buffer <> bytes, read: read}

      {:error, :closed} when allow_close ->
        :closed

      {:error, :timeout} ->
        ensure(false, :deadline_exceeded)

      _ ->
        ensure(false, :invalid_response)
    end
  end

  defp decode(bytes, encoding, cap, deadline) do
    encoding = if is_binary(encoding), do: encoding |> String.trim() |> String.downcase()

    decoded =
      case encoding do
        nil -> bytes
        "identity" -> bytes
        coding when coding in ["gzip", "x-gzip"] -> inflate(bytes, cap, deadline)
        _ -> ensure(false, :invalid_response)
      end

    ensure(byte_size(decoded) <= cap, :limit)
    decoded
  end

  defp inflate(bytes, cap, deadline) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, 31, :error)
      output = inflate_output(z, :zlib.safeInflate(z, bytes), [], 0, cap, deadline)
      :ok = :zlib.inflateEnd(z)
      output
    after
      :zlib.close(z)
    end
  end

  defp inflate_output(z, {status, output}, acc, size, cap, deadline)
       when status in [:continue, :finished] do
    Support.remaining(deadline)
    size = size + IO.iodata_length(output)
    ensure(size <= cap, :limit)
    acc = [output | acc]

    if status == :finished,
      do: IO.iodata_to_binary(Enum.reverse(acc)),
      else: inflate_output(z, :zlib.safeInflate(z, []), acc, size, cap, deadline)
  end

  defp inflate_output(_, _, _, _, _, _), do: ensure(false, :invalid_response)
end
