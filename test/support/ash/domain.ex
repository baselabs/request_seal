defmodule RequestSeal.Test.Ash.Domain do
  @moduledoc false
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(RequestSeal.Test.Ash.Record)
  end
end
