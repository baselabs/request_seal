-module(apply).
-export([run/1]).
run(Fun) -> erlang:apply(Fun, []).
