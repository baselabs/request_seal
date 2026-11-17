-module(named_fun).
-export([run/1]).
run(_) -> fun F(0) -> ok; F(N) -> F(N-1) end.
