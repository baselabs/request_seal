-module(variable_remote).
-export([run/1]).
run(M) -> M:run().
