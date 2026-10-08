defmodule RequestSeal.Test.Ash.Record do
  @moduledoc false
  use Ash.Resource,
    domain: RequestSeal.Test.Ash.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(false)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:tenant_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:tenant_id, :string, allow_nil?: false)
  end

  actions do
    defaults([:read, :create, :destroy])
    destroy(:tenant_destroy)
  end

  policies do
    policy action_type(:read) do
      forbid_unless(actor_present())
      authorize_if(actor_attribute_equals(:role, :reader))
    end

    policy action_type(:destroy) do
      authorize_if(actor_attribute_equals(:role, :admin))
    end

    policy action(:tenant_destroy) do
      authorize_if(RequestSeal.Test.Ash.TenantMatches)
    end

    policy action_type(:create) do
      authorize_if(RequestSeal.Test.Ash.ContentChecked)
    end
  end
end
