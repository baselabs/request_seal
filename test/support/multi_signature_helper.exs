defmodule RequestSeal.MultiSignatureSupport do
  import ExUnit.Assertions

  alias RequestSeal.{
    Body,
    Crypto,
    Custody,
    FieldOccurrence,
    Message,
    Policy,
    PublicKey,
    Quorum,
    TransportFacts
  }

  alias RequestSeal.Custody.Local
  @root Path.join(__DIR__, "../fixtures")
  @corpus :json.decode(File.read!(Path.join(@root, "multi_signature/rfc9421.json")))
  def corpus, do: @corpus
  def unsigned, do: message(@corpus["b2"])
  def vector(label), do: Enum.find(@corpus["signatures"], &(&1["label"] == label))

  def signed(labels \\ ~w(sig-b21 sig-b22 sig-b23 sig-b25 sig-b26)) do
    Enum.reduce(labels, unsigned(), fn label, m -> append(m, vector(label)) end)
  end

  def append(m, v),
    do: %{
      m
      | fields:
          m.fields ++
            [field("Signature-Input", v["signature_input"]), field("Signature", v["signature"])]
    }

  def field(n, v) do
    {:ok, f} = FieldOccurrence.new(%{name: n, value: v, section: :headers, provenance: :caller})
    f
  end

  def add(m, n, v), do: %{m | fields: m.fields ++ [field(n, v)]}

  def strip(m),
    do: %{
      m
      | fields:
          Enum.reject(m.fields, &(String.downcase(&1.name) in ~w(signature signature-input)))
    }

  def rewrite(m, fun),
    do: %{
      m
      | fields:
          Enum.map(m.fields, fn f -> %{f | value: fun.(String.downcase(f.name), f.value)} end)
    }

  def message(p) do
    {:ok, body} =
      Body.new(%{
        state: :retained,
        bytes:
          if(p["kind"] == "request",
            do: ~s[{"hello": "world"}],
            else: ~s[{"busy": true, "message": "Your call is very important to us"}]
          )
      })

    {:ok, transport} = TransportFacts.new(%{})

    attrs = %{
      kind: String.to_existing_atom(p["kind"]),
      fields: Enum.map(p["fields"], fn [n, v] -> field(n, v) end),
      body: body,
      transport: transport,
      trailers: :unavailable
    }

    attrs =
      if p["kind"] == "request",
        do:
          Map.merge(attrs, %{
            method: p["method"],
            raw_target: p["raw_target"],
            target_form: :origin,
            scheme: p["scheme"],
            authority: p["authority"]
          }),
        else:
          Map.merge(attrs, %{status: p["status"], related_request: message(p["related_request"])})

    {:ok, m} = Message.new(attrs)
    m
  end

  def public(name) do
    {:ok, k} = PublicKey.import(File.read!(Path.join(@root, "crypto/#{name}_public.pem")), :pem)
    k
  end

  def material("hmac"),
    do:
      {:hmac,
       File.read!(Path.join(@root, "crypto/hmac.txt")) |> String.trim() |> Base.decode64!()}

  def material(name) do
    [entry] = :public_key.pem_decode(File.read!(Path.join(@root, "crypto/#{name}_private.pem")))
    k = :public_key.pem_entry_decode(entry)

    case name do
      "rsa" -> {:rsa, k}
      "rsa_pss" -> {:rsa, elem(k, 0)}
      "p256" -> {:ec, "P-256", elem(k, 2)}
      "ed25519" -> {:ed25519, elem(k, 2)}
    end
  end

  def signer(name), do: fn alg, base -> Crypto.sign(alg, base, material(name)) end

  def hmac(equivalence \\ "published-secret") do
    {:ok, h} =
      Local.new(
        "hmac-sha256",
        material("hmac"),
        if(equivalence == nil, do: [], else: [equivalence: equivalence])
      )

    h
  end

  def handle_resolver(h, algorithm \\ "hmac-sha256") do
    {:ok, id} = Custody.identity(h)

    fn _ ->
      {:ok,
       %{algorithm: algorithm, key: fn _a, b, s -> Custody.verify(h, b, s) end, identity: id}}
    end
  end

  def resolver(%{keyid: keyid}) do
    case keyid do
      "test-key-rsa-pss" -> {:ok, %{algorithm: "rsa-pss-sha512", key: public("rsa_pss")}}
      "test-key-rsa" -> {:ok, %{algorithm: "rsa-v1_5-sha256", key: public("rsa")}}
      "test-key-ed25519" -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}}
      "test-key-ecc-p256" -> {:ok, %{algorithm: "ecdsa-p256-sha256", key: public("p256")}}
      "test-shared-secret" -> handle_resolver(hmac()).(%{})
      _ -> :error
    end
  end

  def policy(opts \\ []) do
    attrs = %{
      algorithms: Crypto.algorithms(),
      components: "()",
      key_resolver: &resolver/1,
      freshness: :not_evaluated,
      content: :not_required,
      replay: :not_required,
      field_schemas: schemas()
    }

    {:ok, p} = Policy.new(Map.merge(attrs, Map.new(opts)))
    p
  end

  def slot(id, opts \\ []),
    do:
      Map.merge(
        %{
          id: id,
          policy: policy(),
          required: true,
          label: nil,
          tag: nil,
          principal: nil,
          role: nil
        },
        Map.new(opts)
      )

  def verify_quorum(message, quorum, opts \\ []),
    do: assert_unique_labels(RequestSeal.verify_quorum(message, quorum, opts))

  defp assert_unique_labels({:ok, result} = outcome) do
    labels = Enum.map(result.qualifying, & &1.label)
    assert length(labels) == length(Enum.uniq(labels))
    assert map_size(result.signatures) == length(labels)
    outcome
  end

  defp assert_unique_labels(outcome), do: outcome

  def quorum(slots, opts \\ []) do
    {:ok, q} =
      Quorum.new(
        Map.merge(
          %{mode: :all, unit: :key, slots: slots, unexpected: :ignore, invalid: :ignore},
          Map.new(opts)
        )
      )

    q
  end

  def error(result, reason, layer \\ :quorum) do
    assert {:error,
            %RequestSeal.Error{reason: ^reason, layer: ^layer, detail: detail, retryable: false} =
              e} = result

    assert detail == nil or is_atom(detail)
    refute inspect(e) =~ "test-key"
    refute inspect(e) =~ "published-secret"
    e
  end

  def schemas,
    do: %{
      "signature-input" => RequestSeal.SignatureFields.schema(:dictionary),
      "signature" => RequestSeal.SignatureFields.schema(:dictionary, [:bytes], false),
      "content-digest" => RequestSeal.SignatureFields.schema(:dictionary, [:bytes], false)
    }

  def local_sign(m, label, input, name \\ "ed25519", alg \\ "ed25519") do
    keyid =
      case name do
        "ed25519" -> "test-key-ed25519"
        "rsa_pss" -> "test-key-rsa-pss"
        "rsa" -> "test-key-rsa"
        "p256" -> "test-key-ecc-p256"
      end

    input =
      if String.contains?(input, ";keyid="),
        do: input,
        else: input <> ";keyid=\"" <> keyid <> "\""

    {:ok, m} =
      RequestSeal.sign(m, %{label: label, signature_input: input, algorithm: alg}, signer(name),
        field_schemas: schemas()
      )

    m
  end
end
