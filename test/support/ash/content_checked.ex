defmodule RequestSeal.Test.Ash.ContentChecked do
  @moduledoc false
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_), do: "requires checked message content"

  @impl true
  def match?(_, %{context: context}, _),
    do: get_in(context, [:request_seal, :content]) == :checked
end
