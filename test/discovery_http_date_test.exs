defmodule RequestSeal.DiscoveryHTTPDateTest.Parser do
  @moduledoc false
  # Execute the private parser's actual source bodies without exposing a public
  # library API or letting HTTP field trimming alter the characterization inputs.
  @source Path.expand("../lib/request_seal/discovery.ex", __DIR__)
  @external_resource @source
  {:defmodule, _, [_, [do: {:__block__, _, definitions}]]} =
    @source |> File.read!() |> Code.string_to_quoted!()

  for {:defp, metadata, [{name, _, _}, _] = arguments} <- definitions,
      name in [:http_date, :obsolete_date] do
    kind = if name == :http_date, do: :def, else: :defp
    Code.eval_quoted({kind, metadata, arguments}, [], __ENV__)
  end
end

defmodule RequestSeal.DiscoveryHTTPDateTest do
  use ExUnit.Case, async: true
  alias RequestSeal.DiscoveryHTTPDateTest.Parser

  # RFC 9110 Section 5.6.7 examples and mutations characterize acceptance;
  # they are parser inputs, not claims of counterpart interoperability.
  # https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7
  @now DateTime.to_unix(~U[2026-10-08 00:00:00Z])
  @valid "1994-11-06T08:49:37Z"
  @forms [
    "Sun, 06 Nov 1994 08:49:37 GMT",
    "Sunday, 06-Nov-94 08:49:37 GMT",
    "Sun Nov  6 08:49:37 1994"
  ]

  @cases (
           valid = for value <- @forms, do: {value, @now, @valid}

           ranges =
             for {day, month, year, hour, minute, second} <- [
                   {"32", "Nov", "1994", "08", "49", "37"},
                   {"30", "Feb", "1994", "08", "49", "37"},
                   {"06", "Nov", "1994", "24", "49", "37"},
                   {"06", "Nov", "1994", "08", "60", "37"},
                   {"06", "Nov", "1994", "08", "49", "61"}
                 ],
                 value <- [
                   "Sun, #{day} #{month} #{year} #{hour}:#{minute}:#{second} GMT",
                   "Sunday, #{day}-#{month}-94 #{hour}:#{minute}:#{second} GMT",
                   "Sun #{month} #{day} #{hour}:#{minute}:#{second} #{year}"
                 ],
                 do: {value, @now, nil}

           years = [
             {"Sun, 06 Nov 0000 08:49:37 GMT", @now, "0000-11-06T08:49:37Z"},
             {"Sun Nov  6 08:49:37 0000", @now, "0000-11-06T08:49:37Z"},
             {"Sunday, 06-Nov-0000 08:49:37 GMT", @now, nil},
             {"Sun, 06 Nov 10000 08:49:37 GMT", @now, nil},
             {"Sunday, 06-Nov-10000 08:49:37 GMT", @now, nil},
             {"Sun Nov  6 08:49:37 10000", @now, nil}
           ]

           lexical =
             for value <- @forms,
                 changed <- [
                   String.replace(value, "Nov", "nov"),
                   String.replace(value, ["Sunday", "Sun"], &String.downcase/1),
                   " " <> value,
                   value <> " ",
                   String.replace(value, " ", "  ", global: false),
                   String.replace(value, " ", "\t", global: false),
                   value <> "garbage",
                   value <> "\r\n"
                 ],
                 do: {changed, @now, nil}

           numbers =
             for day <- ["+9", " 9"],
                 value <- [
                   "Sun, #{day} Nov 1994 08:49:37 GMT",
                   "Sunday, #{day}-Nov-94 08:49:37 GMT",
                   "Sun Nov #{day} 08:49:37 1994"
                 ],
                 do:
                   {value, @now,
                    if(value == "Sun Nov  9 08:49:37 1994", do: "1994-11-09T08:49:37Z")}

           weekdays =
             for value <- @forms,
                 do: {String.replace(value, "Sun", "Mon"), @now, @valid}

           # With a 2026 clock the inclusive 50-year future cutoff is 2076:
           # 00..76 map to 2000..2076; 77..99 map to 1977..1999.
           pivot =
             for year <- 0..99 do
               short = year |> Integer.to_string() |> String.pad_leading(2, "0")
               full = if year <= 76, do: 2000 + year, else: 1900 + year
               {"Sunday, 06-Nov-#{short} 08:49:37 GMT", @now, "#{full}-11-06T08:49:37Z"}
             end

           clocks =
             for {now, year} <- [
                   {~U[1960-01-01 00:00:00Z], 1994},
                   {~U[2000-01-01 00:00:00Z], 1994},
                   {~U[2050-01-01 00:00:00Z], 2094}
                 ],
                 do: {Enum.at(@forms, 1), DateTime.to_unix(now), "#{year}-11-06T08:49:37Z"}

           valid ++
             ranges ++
             years ++
             lexical ++
             numbers ++
             weekdays ++
             pivot ++
             clocks ++
             [
               {"Sun Nov 06 08:49:37 1994", @now, @valid},
               {"", @now, nil},
               {String.duplicate("x", 65_536), @now, nil},
               {hd(@forms) <> String.duplicate(" ", 65_536), @now, nil}
             ]
         )

  def cases, do: Enum.uniq(@cases)

  for {input, now, expected} <- Enum.uniq(@cases) do
    @input input
    @clock now
    @expected expected
    test "HTTP-date #{inspect(input, limit: 80, printable_limit: 80)} at #{now}" do
      expected =
        if @expected do
          {:ok, datetime, 0} = DateTime.from_iso8601(@expected)
          DateTime.to_unix(datetime)
        end

      assert Parser.http_date(@input, @clock) == expected
    end
  end

  test "absent HTTP-date stays absent" do
    assert Parser.http_date(nil, @now) == nil
  end
end
