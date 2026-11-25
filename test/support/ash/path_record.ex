defmodule RequestSeal.Test.Ash.PathDomain do
  @moduledoc false
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(RequestSeal.Test.Ash.PathRecord)
  end
end

defmodule RequestSeal.Test.Ash.PathRecord do
  @moduledoc false
  use Ash.Resource,
    domain: RequestSeal.Test.Ash.PathDomain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(true)
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
    defaults([:create, :read, :destroy])
  end

  policies do
    policy action_type(:destroy) do
      authorize_if(RequestSeal.Test.Ash.TenantMatches)
    end
  end
end
