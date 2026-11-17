-module(on_load).
-on_load(init/0).
-export([run/1]).
init() -> ok.
run(X) -> X.
