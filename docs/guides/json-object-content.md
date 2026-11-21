# Decode strict JSON object content

Decode bounded JSON objects consistently, or have JWE decryption decode them
only after authentication. With `content: :object`, a decoding failure returns
only an error, with no plaintext or partial object.

Install RequestSeal in your Mix project, then run these blocks in `iex -S mix`:

```elixir
{:request_seal, "~> 2.0"}
```

## Decode object bytes

`RequestSeal.JOSE.decode_object/2` accepts decoded JSON bytes, not compact JOSE
or a Base64url segment. It parses; it does not authenticate the bytes. Its only
option is the required `max_bytes:`, an integer from 1 through 1,048,576.

```elixir
{:ok, %{"active" => true, "count" => 3, "note" => nil}} =
  RequestSeal.JOSE.decode_object(~s({"active":true,"count":3,"note":null}), max_bytes: 1024)

{:error, %{reason: :duplicate_member, layer: :input}} =
  RequestSeal.JOSE.decode_object(~s({"count":1,"count":2}), max_bytes: 1024)
{:error, %{reason: :invalid_header, layer: :input}} =
  RequestSeal.JOSE.decode_object(~s({"count":1.5}), max_bytes: 1024)
{:error, %{reason: :invalid_header, layer: :input}} = RequestSeal.JOSE.decode_object("[]", max_bytes: 1024)
{:error, %{reason: :limit, layer: :input}} = RequestSeal.JOSE.decode_object("{}", max_bytes: 1)
{:error, %{reason: :invalid_options, layer: :input}} = RequestSeal.JOSE.decode_object("{}", [])
```

The input must be one UTF-8 object. Duplicate member names reject at every
depth, including names that become equal after escape decoding. Floats and
exponent notation reject. Objects have at most 64 members, arrays at most 64
elements, and nesting at most four container levels, counting the root object.
Strings and member names have at most 16,384 UTF-8 bytes. Integers are within
±999,999,999,999,999. JSON null becomes `nil`; object keys remain strings.

These explicit bounds narrow [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html)
JSON and share the protected-header decoder's rules. This is not a JSON schema
or a JWT claims validator. Apply your field and application rules after success.

## Authenticate and decode a JWE

This local example uses [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394.html)
AES key wrapping and [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html)
authenticated content encryption. The wrapping key is generated inside custody.

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate({:jwe, "A256KW"}, [])
header = [{"alg", "A256KW"}, {"enc", "A256GCM"}, {"cty", "application/json"}]
bytes = ~s({"active":true,"count":3})
{:ok, token} = RequestSeal.JOSE.JWE.encrypt(header, bytes, handle)

policy = %{
  algorithms: ["A256KW"],
  encryption: ["A256GCM"],
  max_plaintext: 4096,
  timeout: 5_000,
  resolve_timeout: 1_000,
  unwrap_timeout: 1_000,
  protected: %{expected: %{"cty" => "application/json"}, permitted: []},
  key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: handle}} end,
  content: :object
}

{:ok, result} = RequestSeal.JOSE.JWE.decrypt(token, policy)
%{"active" => true, "count" => 3} = result.object
^bytes = result.plaintext
:valid = result.recipient_integrity
:not_evaluated = result.authorization
```

Omitting `content:` selects binary content; explicit `content: :binary` has the
same behavior and leaves `result.object` as `nil`. `:object` uses `max_plaintext`
as its byte limit and preserves the authenticated `plaintext` on success. It
adds no decoder options. The protected `cty` above is public expected context;
the library does not infer decoding from `cty`.

Authentication precedes decoding. Even a correctly encrypted object can violate
the decoder contract. Such a failure has no success result and no plaintext:

```elixir
{:ok, invalid_object_token} = RequestSeal.JOSE.JWE.encrypt(header, ~s({"count":1,"count":2}), handle)
{:error, decode_error} = RequestSeal.JOSE.JWE.decrypt(invalid_object_token, policy)
:duplicate_member = decode_error.reason
:input = decode_error.layer
false = Map.has_key?(decode_error, :plaintext)
false = Map.has_key?(decode_error, :object)

[protected, encrypted_key, iv, ciphertext, tag] = String.split(invalid_object_token, ".")
<<first, rest::binary>> = Base.url_decode64!(tag, padding: false)
changed_tag = Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)
forged = Enum.join([protected, encrypted_key, iv, ciphertext, changed_tag], ".")
{:error, %{reason: :decryption_failed, layer: :crypto}} = RequestSeal.JOSE.JWE.decrypt(forged, policy)
```

If you decrypt binary content and decode it yourself, your caller has already
received plaintext when decoding fails. Select `:object` when that exposure is
unacceptable. Payloads outside these object bounds require binary content and
the application's own decoder. Recipient integrity alone does not authenticate
a sender or authorize use of any decoded field.

## Decode each batch item

`content: :object` also applies to `JWE.decrypt_many/2`. A successful outer tuple
contains positional results, including individual decoding errors. A failed
entry contains neither plaintext nor a partial object; good neighbors keep
their authenticated objects. The library returns one final list.

```elixir
batch_policy =
  policy
  |> Map.put(:protected, %{permitted: []})
  |> Map.merge(%{max_tokens: 2, max_total_input: 16_384, max_total_plaintext: 8192})

items =
  for compact <- [token, invalid_object_token] do
    %{token: compact, expected: %{"cty" => "application/json"}}
  end

{:ok, [
  {:ok, %{object: %{"active" => true, "count" => 3}, plaintext: ^bytes}},
  {:error, %{reason: :duplicate_member, layer: :input}}
]} = RequestSeal.JOSE.JWE.decrypt_many(items, batch_policy)

:ok = RequestSeal.Custody.release(handle)
```

## Error reasons

`decode_object/2` returns bounded `RequestSeal.JOSE.Error` structs, all at layer
`:input`: `:invalid_options` for missing, extra, duplicate, or invalid options;
`:invalid_header` for malformed JSON, invalid UTF-8, floats, or a nonobject root;
`:duplicate_member` for repeated names; and `:limit` for exceeded byte, depth,
container, string, or integer bounds. None is retryable. JWE can also return its
normal admission, resolver, authentication, and deadline errors before a decoder
result exists. See [JOSE](jose.md) for protected maps and phase budgets.
