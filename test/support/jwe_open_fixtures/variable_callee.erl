-module(variable_callee).
-export([run/1]).
run(Fun) -> Fun().
