defmodule RequestSeal.PlugScopeTest.Forwarded do
  @moduledoc false
  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    conn
    |> Plug.Conn.put_private(:scope_forward, {conn.script_name, conn.path_info})
    |> RequestSeal.Plug.Scope.call(conn.private.scope_options)
  end
end

defmodule RequestSeal.PlugScopeTest.Router do
  @moduledoc false
  use Plug.Router

  plug :match
  plug :dispatch

  forward "/teams", to: RequestSeal.PlugScopeTest.Forwarded
end

defmodule RequestSeal.PlugScopeTest do
  use ExUnit.Case, async: true

  alias RequestSeal.Plug, as: SealPlug
  alias RequestSeal.Plug.{Scope, Verify}
  alias RequestSeal.PlugScopeTest.Router
  alias RequestSeal.Test.Ash.PathRecord
  import RequestSeal.SignedPathTestSupport

  @covered ~s[("@method" "@path")]

  test "uses covered bytes across a router forward and maps the tenant into Ash" do
    conn = verified("/teams/alpha/items", @covered) |> forward_through_router()
    assert conn.private.scope_forward == {["teams"], ["alpha", "items"]}

    assert {:ok, %{tenant: "alpha", captures: %{"tenant" => "alpha"}}} = SealPlug.scope(conn)

    binding = %{actor: fn _ -> :error end, unattributed: :anonymous}
    assert {:ok, scope} = Scope.ash_scope(conn, binding)
    assert scope.tenant == "alpha"
    assert scope.authorize?

    assert {:error, %{reason: :invalid_binding}} =
             Scope.ash_scope(conn, Map.put(binding, :tenant, {:value, "other"}))

    verify =
      Verify.init(policy: fn -> raise "must not run" end, label: "other", on_reject: :continue)
    conn = Verify.call(conn, verify)
    assert :error = SealPlug.scope(conn)
    assert {:error, %{reason: :scope_unbound}} = Scope.ash_scope(conn, binding)
  end

  test "verification and exact coverage are required" do
    assert refused(Plug.Test.conn(:get, "/teams/alpha"), :unverified)
    assert refused(verified("/teams/alpha", ~s[("@method")]), :path_not_covered)

    conn = verified("/teams/alpha", @covered)
    assert refused(%{conn | path_info: ["teams", "other"]}, :path_rewritten)
  end

  test "ambiguous encoding and invalid templates or capture values fail closed" do
    for path <- [
          "/teams//alpha",
          "/teams/alpha/",
          "/teams/alpha/%2E%2e",
          "/teams/al%2Fpha",
          "/teams/%252F",
          "/teams/%00",
          "/teams/alpha/%5C",
          "/teams/%61lpha"
        ] do
      assert refused(verified(path, @covered), :ambiguous_path)
    end

    assert refused(verified("/groups/alpha", @covered), :template_mismatch)
    assert refused(verified("/teams/al.pha", @covered), :invalid_scope)

    for bad <- ["/teams/:tenant/:tenant", "/teams/*/:tenant", "/teams/:other"] do
      assert {:error, %{reason: :invalid_options}} = Scope.new(attrs(template: bad))
    end

    assert {:error, %{reason: :invalid_options}} = Scope.new(attrs(principal_tenant: nil))
    assert {:error, %{reason: :invalid_options}} = Scope.new(attrs() ++ [tenant: :tenant])
  end

  test "the router rejects alternate spellings before binding a tenant" do
    for {path, reason} <- [
          {"/teams/%61lpha/items", :ambiguous_path},
          {"/teams/Alpha/items", :invalid_scope}
        ] do
      conn = verified(path, @covered) |> forward_through_router()
      assert :error = SealPlug.scope(conn)
      assert {:error, %{reason: ^reason}} = conn.private.request_seal.scope
    end
  end

  test "a fully parsed JSON body is inspected recursively before lookup" do
    target = "/teams/alpha/items"
    accepted = verified(target, @covered, body: ~s({"items":[{"count":1}]}))
    assert {:ok, %{tenant: "alpha"}} = SealPlug.scope(Scope.call(accepted, options()))
    assert refused(%{accepted | body_params: %URI{}}, :body_uninspected)

    nested = ~s({"items":[{"tenant_id":"other"}]})
    assert refused(verified(target, @covered, body: nested), :scope_in_body)
    assert refused(
             verified(target, @covered, body: nested, parse_body: false),
             :body_uninspected
           )
  end

  test "nested opaque and unfetched values fail closed, while uploads stay opaque" do
    target = "/teams/alpha/items"
    conn = verified(target, @covered, body: ~s({"items":[{"count":1}]}))

    for value <- [%Plug.Conn.Unfetched{aspect: :body_params}, %URI{}] do
      assert refused(%{conn | body_params: %{"items" => [%{"value" => value}]}}, :body_uninspected)
      assert refused(%{conn | query_params: %{"items" => [value]}}, :invalid_query)
    end

    upload = %Plug.Upload{filename: "tenant_id", path: "/unused", content_type: "text/plain"}
    conn = %{conn | body_params: %{"items" => [%{"file" => upload}]}}
    assert {:ok, %{tenant: "alpha"}} = SealPlug.scope(Scope.call(conn, options()))
    assert refused(%{conn | body_params: %{"items" => [%{"tenant_id" => upload}]}}, :scope_in_body)
  end

  test "body inspection finds selectors discarded by form and JSON parsers" do
    target = "/teams/alpha"
    forms = [content_type: "application/x-www-form-urlencoded", parsers: [:urlencoded]]

    for {encoded, merged} <- [
          {"filters%5Btenant_id%5D=other&filters=plain", "plain"},
          {"filters%5Btenant_id%5D=other&filters%5B%5D=plain", ["plain"]}
        ] do
      conn = verified(target, @covered, [body: encoded] ++ forms)
      assert conn.body_params == %{"filters" => merged}
      assert refused(conn, :scope_in_body)
    end

    json =
      for body <- [
            ~s({"filters":"plain","filters":{"tenant_id":"other"}}),
            ~s({"filters":{"tenant_id":"other"},"filters":"plain"})
          ],
          do: verified(target, @covered, body: body)

    assert Enum.any?(json, &(&1.body_params == %{"filters" => "plain"}))
    Enum.each(json, &assert(refused(&1, :scope_in_body)))

    clean = verified(target, @covered, [body: "filters=tenant_id"] ++ forms)
    assert {:ok, %{tenant: "alpha"}} = SealPlug.scope(Scope.call(clean, options()))
  end

  test "refuses a fully parsed multipart body without raw selector evidence" do
    body = "--sample\r\ncontent-disposition: form-data; name=\"note\"\r\n\r\nok\r\n--sample--\r\n"

    conn =
      verified("/teams/alpha", @covered,
        body: body,
        content_type: "multipart/form-data; boundary=sample",
        parsers: [:multipart]
      )

    assert conn.body_params == %{"note" => "ok"}
    assert refused(conn, :body_uninspected)
  end

  test "binds a verified request with the preceding private state shape" do
    conn = verified("/teams/alpha", @covered)
    state = Map.delete(conn.private.request_seal, :scope)
    conn = Plug.Conn.put_private(conn, :request_seal, state)

    assert :error = RequestSeal.Plug.scope(conn)
    assert {:ok, %{tenant: "alpha"}} = RequestSeal.Plug.scope(Scope.call(conn, options()))
  end

  test "the principal lookup is cancelled at its configured deadline" do
    parent = self()

    lookup = fn _ ->
      send(parent, {:lookup, self()})

      receive do
        :complete -> {:ok, "alpha"}
      end
    end

    conn = verified("/teams/alpha/items", @covered)
    assert refused(conn, :tenant_lookup_timeout, options(principal_tenant: lookup, lookup_timeout: 100))
    assert_received {:lookup, worker}
    refute Process.alive?(worker)
  end

  test "a forwarded signed path scopes a real Ash policy on own and foreign records" do
    conn = verified("/teams/alpha/items", @covered) |> forward_through_router()
    binding = %{actor: fn _ -> :error end, unattributed: :anonymous}
    assert {:ok, %{tenant: "alpha", actor: nil, principal: :unattributed} = scope} =
             Scope.ash_scope(conn, binding)

    own = row("alpha")
    foreign = row("beta")
    opts = RequestSeal.Ash.Scope.to_opts(scope)
    assert {:error, %Ash.Error.Forbidden{}} = Ash.destroy(foreign, opts)
    assert :ok = Ash.destroy(own, opts)

    assert {:ok, []} = Ash.read(PathRecord, tenant: "alpha", authorize?: false)
    assert {:ok, [%{id: id}]} = Ash.read(PathRecord, tenant: "beta", authorize?: false)
    assert id == foreign.id
  end

  test "refuses competing selectors in header, encoded query, and fetched body" do
    conn = verified("/teams/alpha", @covered)
    assert refused(Plug.Conn.put_req_header(conn, "x-tenant", "alpha"), :scope_in_header)
    assert refused(%{conn | body_params: %{tenant: "alpha"}}, :scope_in_body)

    query = verified("/teams/alpha?%74enant%5Bid%5D=alpha", @covered)
    assert refused(%{query | query_params: %{}}, :scope_in_query)
    assert refused(%{query | query_string: ""}, :invalid_query)
  end

  test "refuses a captured competing header even when an intervening plug removes it" do
    conn =
      verified("/teams/alpha", @covered, headers: [{"x-tenant-id", "other"}])
      |> Plug.Conn.delete_req_header("x-tenant-id")

    assert Plug.Conn.get_req_header(conn, "x-tenant-id") == []
    assert refused(conn, :scope_in_header)
  end

  test "rejects encoded selector names lost to scalar overrides and list finalization" do
    for {query, value} <- [
          {"filters%5B%74enant_id%5D=other&filters=plain", "plain"},
          {"filters%5Btenant_id%5D=other&filters%5B%5D=plain", ["plain"]}
        ] do
      conn =
        verified("/teams/alpha?" <> query, @covered)
        |> Plug.Conn.fetch_query_params()

      assert conn.query_params == %{"filters" => value}
      assert refused(conn, :scope_in_query)
    end

    clean = verified("/teams/alpha?filters=tenant_id&filters%5B%5D=tenant", @covered)
    assert {:ok, %{tenant: "alpha"}} = SealPlug.scope(Scope.call(clean, options()))
  end

  test "requires exact principal agreement and removes scope on repeat" do
    conn = verified("/teams/alpha", @covered)

    for callback <- [
          fn _ -> {:ok, "other"} end,
          fn _ -> :platform end,
          fn _ -> raise "unavailable" end,
          fn _ -> throw(:bad) end,
          fn _ -> exit(:bad) end
        ] do
      assert refused(conn, :tenant_mismatch, options(principal_tenant: callback))
    end

    assert refused(Scope.call(conn, options()), :already_scoped)
    halted = Scope.call(conn, options(principal_tenant: fn _ -> :error end, on_reject: {:halt, 403}))
    assert halted.halted and halted.status == 403 and halted.resp_body == ""
  end

  test "validates lowercase UUIDs without case folding" do
    uuid = "a1a4a110-60db-47d3-a0ba-506c1387dc29"
    opts = options(validator: :uuid, principal_tenant: fn _ -> {:ok, uuid} end)
    assert {:ok, %{tenant: ^uuid}} =
             SealPlug.scope(Scope.call(verified("/teams/" <> uuid, @covered), opts))
    assert refused(verified("/teams/" <> String.upcase(uuid), @covered), :invalid_scope, opts)
  end

  defp forward_through_router(conn) do
    conn
    |> Plug.Conn.put_private(:scope_options, options())
    |> Router.call(Router.init([]))
  end

  defp row(tenant) do
    PathRecord
    |> Ash.Changeset.for_create(:create, %{}, tenant: tenant, authorize?: false)
    |> Ash.create!()
  end

  defp refused(conn, reason, options \\ options()) do
    conn = Scope.call(conn, options)
    assert :error = SealPlug.scope(conn)
    assert {:error, %{reason: ^reason, stage: :scope, source: nil}} = conn.private.request_seal.scope
    true
  end

  defp options(overrides \\ []), do: Scope.init(attrs(overrides))

  defp attrs(overrides \\ []) do
    Keyword.merge(
      [
        template: "/teams/:tenant/*",
        tenant: :tenant,
        principal_tenant: fn _ -> {:ok, "alpha"} end,
        on_reject: :continue
      ],
      overrides
    )
  end
end
