-module(accepted).
-export([run/1, forms/1]).
run(X) ->
    A = {ok, [X | []], #{key => <<1, 2, 3>>}},
    B = case X of true -> 1; _ -> 2 end,
    C = if B > 0 -> B + 1; true -> 0 end,
    receive {value, V} -> {A, V} after 0 -> {A, C} end.
forms(X) ->
    Values = [N + 1 || N <- [1, 2], N > 0],
    Binary = << <<N:8>> || N <- Values >>,
    Map = #{key => X},
    Updated = Map#{key := Binary},
    Predicate = lists:all(fun(N) -> is_integer(N) end, Values),
    try {Updated, Predicate, not false, -1, 1.0, $a, "text"}
    catch throw:Reason -> {refused, Reason}
    after self()
    end.
