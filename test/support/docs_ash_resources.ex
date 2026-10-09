defmodule AshApp.Document do
  use Ash.Resource,
    domain: AshApp.Documents,
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
    defaults([:read])
  end

  policies do
    policy action_type(:read) do
      authorize_if(actor_attribute_equals(:role, :reader))
    end
  end
end

defmodule AshApp.Documents do
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(AshApp.Document)
  end
end
