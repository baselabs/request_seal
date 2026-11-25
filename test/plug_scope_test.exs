defmodule RequestSeal.PlugScopeTest do
  use ExUnit.Case, async: true

  alias RequestSeal.Plug, as: SealPlug
  alias RequestSeal.Plug.{Scope, Verify}
  import RequestSeal.SignedPathTestSupport

  @covered ~s[("@method" "@path")]

  test "uses covered bytes across a router forward and maps the tenant into Ash" do
    conn = verified("/teams/%61lpha/items", @covered)
    conn = %{conn | script_name: ["teams"], path_info: ["%61lpha", "items"]}
    conn = Scope.call(conn, options())

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
          "/teams/alpha/%5C"
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

  test "refuses competing selectors in header, encoded query, and fetched body" do
    conn = verified("/teams/alpha", @covered)
    assert refused(Plug.Conn.put_req_header(conn, "x-tenant", "alpha"), :scope_in_header)
    assert refused(%{conn | body_params: %{tenant: "alpha"}}, :scope_in_body)

    query = verified("/teams/alpha?%74enant%5Bid%5D=alpha", @covered)
    assert refused(%{query | query_params: %{}}, :scope_in_query)
    assert refused(%{query | query_string: ""}, :invalid_query)
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
