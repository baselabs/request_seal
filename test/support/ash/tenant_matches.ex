defmodule RequestSeal.Test.Ash.TenantMatches do
  @moduledoc false
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_), do: "requires the original record tenant to match the action tenant"

  @impl true
  def match?(_, %{changeset: %{data: %{tenant_id: tenant_id}, to_tenant: tenant}}, _),
    do: not is_nil(tenant) and tenant_id == tenant

  def match?(_, _, _), do: false
end
