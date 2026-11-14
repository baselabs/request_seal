defmodule RequestSeal.Test.UnwrapCustodian do
  @moduledoc false
  @behaviour RequestSeal.Custody
  alias RequestSeal.Custody.{Context, Sink}
  alias RequestSeal.JOSE.KeyManagement

  def start(mode, observer) do
    owner = self()

    holder =
      spawn(fn ->
        Process.flag(:sensitive, true)
        monitor = Process.monitor(owner)

        receive do
          {:unwrap, runner, items, sink, context} ->
            send(observer, {:holder_ready, self(), runner, sink, context})
            receive do: (:deliver -> :ok)
            [first | rest] = items
            deliver(first, sink)
            send(observer, {:prefix_sent, self()})

            case mode do
              :stall ->
                receive do: ({:DOWN, ^monitor, _, _, _} -> :ok)

              :error ->
                send(runner, {:summary, {:error, :custodian_failure}})

              :lost ->
                send(runner, {:summary, :ok})

              :ok ->
                send(runner, {:summary, :ok})

              :duplicates ->
                {index, _, _, _} = first
                Sink.deliver(sink, index, :error)
                Sink.deliver(sink, 100_000, {:ok, <<0::256>>})

                Enum.each(rest, fn {i, _, _, _} ->
                  outcome = if rem(i, 2) == 1, do: {:ok, <<0>>}, else: :malformed
                  Sink.deliver(sink, i, outcome)
                end)

                send(runner, {:summary, :ok})
            end

          {:DOWN, ^monitor, _, _, _} ->
            :ok
        end
      end)

    %RequestSeal.KeyHandle{
      custodian: __MODULE__,
      algorithm: {:jwe, "A256KW"},
      capabilities: [:unwrap],
      ref: fn -> holder end
    }
  end

  defp deliver({index, encrypted, params, bits}, sink) do
    kek = Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

    outcome =
      case KeyManagement.unwrap("A256KW", encrypted, params, {:aes, kek}) do
        {:ok, cek} when bit_size(cek) == bits -> {:ok, cek}
        _ -> :error
      end

    Sink.deliver(sink, index, outcome)
  end

  @impl true
  def unwrap(ref, {:jwe, "A256KW"}, items, sink, context) do
    holder = ref.()
    send(holder, {:unwrap, self(), items, sink, context})

    receive do
      {:summary, result} -> result
    after
      max(Context.remaining(context), 0) -> {:error, :deadline_exceeded}
    end
  end

  @impl true
  def sign(_, _, _, _), do: {:error, :unsupported_operation}
  @impl true
  def public_key(_), do: {:error, :no_public_key}
  @impl true
  def identity(_), do: %RequestSeal.KeyIdentity{kind: :unknown, value: nil}
  @impl true
  def release(ref, _) do
    holder = ref.()
    monitor = Process.monitor(holder)
    Process.unlink(holder)
    Process.exit(holder, :kill)
    receive do: ({:DOWN, ^monitor, _, ^holder, _} -> :ok)
  end
end
