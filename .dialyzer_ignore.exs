# Exact-entry exclusions for `mix dialyzer`; each names one reported warning
# (file, warning type, line), so any new or moved warning still fails the
# gate. Reviewed 2026-10-16 during dialyxir adoption, after the review-repair
# pass, after the repair review, and after the final format. Families
# (deliberate idioms or analysis-surface artifacts, not open defects):
#
# ensure-false: `ensure(false, reason)` — the deliberate always-fail call
#   idiom; dialyzer's success typing for ensure/2 admits only its true branch.
# defensive: dead mapping clauses kept deliberately so widened upstream
#   error reasons map to bounded reasons instead of crashing (the C1 pattern).
# mapset: MapSet opaque-term analysis through untyped private helpers; no
#   opaqueness violation at the API level.
# dep: Finch's own PLT-internal unknown types; not this package's analysis
#   surface (Finch enters the PLT via plt_add_apps so adapter calls resolve).
[
  {"lib/request_seal/crypto.ex", :call, 213},
  {"lib/request_seal/crypto.ex", :call, 229},
  {"lib/request_seal/crypto.ex", :call, 259},
  {"lib/request_seal/custody.ex", :call, 419},
  {"lib/request_seal/custody/local.ex", :call, 448},
  {"lib/request_seal/custody/local.ex", :call, 451},
  {"lib/request_seal/custody/local.ex", :call, 564},
  {"lib/request_seal/custody/local.ex", :call, 583},
  {"lib/request_seal/custody/local.ex", :call, 664},
  {"lib/request_seal/custody/local.ex", :call, 682},
  {"lib/request_seal/custody/local.ex", :call, 699},
  {"lib/request_seal/custody/local.ex", :call, 715},
  {"lib/request_seal/custody/local.ex", :call, 746},
  {"lib/request_seal/custody/local.ex", :call, 755},
  {"lib/request_seal/custody/ssh_agent.ex", :call, 208},
  {"lib/request_seal/custody/ssh_agent.ex", :call, 218},
  {"lib/request_seal/custody/ssh_agent.ex", :call, 228},
  {"lib/request_seal/custody/ssh_agent/wire.ex", :call, 87},
  {"lib/request_seal/custody/ssh_agent/wire.ex", :call, 102},
  {"lib/request_seal/custody/ssh_agent/wire.ex", :call, 120},
  {"lib/request_seal/custody/support.ex", :call, 18},
  {"lib/request_seal/custody/support.ex", :call, 19},
  {"lib/request_seal/discovery.ex", :call, 430},
  {"lib/request_seal/discovery.ex", :call, 549},
  {"lib/request_seal/discovery/cache.ex", :call, 444},
  {"lib/request_seal/discovery/http1.ex", :call, 46},
  {"lib/request_seal/discovery/http1.ex", :call, 119},
  {"lib/request_seal/discovery/http1.ex", :call, 160},
  {"lib/request_seal/discovery/http1.ex", :call, 164},
  {"lib/request_seal/discovery/http1.ex", :call, 289},
  {"lib/request_seal/discovery/http1.ex", :call, 292},
  {"lib/request_seal/discovery/http1.ex", :call, 304},
  {"lib/request_seal/discovery/http1.ex", :call, 336},
  {"lib/request_seal/discovery/source.ex", :call, 218},
  {"lib/request_seal/discovery/source.ex", :call, 219},
  {"lib/request_seal/discovery/source.ex", :call, 223},
  {"lib/request_seal/discovery/support.ex", :call, 19},
  {"lib/request_seal/discovery/support.ex", :call, 40},
  {"lib/request_seal/discovery/support.ex", :call, 42},
  {"lib/request_seal/discovery/transport.ex", :call, 27},
  {"lib/request_seal/discovery/transport.ex", :call, 69},
  {"lib/request_seal/discovery/transport.ex", :call, 92},
  {"lib/request_seal/public_key.ex", :call, 250},
  {"lib/request_seal/public_key.ex", :call, 296},
  {"lib/request_seal/public_key.ex", :call, 326},
  {"lib/request_seal/public_key.ex", :call, 364},
  {"lib/request_seal/public_key.ex", :call, 374},
  {"lib/request_seal/public_key.ex", :call, 380},
  {"lib/request_seal/public_key.ex", :call, 466},
  {"lib/request_seal/public_key.ex", :call, 513},
  {"lib/request_seal/accept_signature.ex", :pattern_match_cov, 283},
  {"lib/request_seal/authentication.ex", :pattern_match, 614},
  {"lib/request_seal/custody/local.ex", :pattern_match, 707},
  {"lib/request_seal/signing.ex", :pattern_match_cov, 431},
  {"lib/request_seal/web_bot_auth.ex", :pattern_match, 1},
  {"lib/request_seal/structured_fields.ex", :call_without_opaque, 663},
  {"lib/request_seal/structured_fields.ex", :call_without_opaque, 724},
  {"lib/request_seal/structured_fields.ex", :call_with_opaque, 735},
  {"lib/request_seal/structured_fields/schema.ex", :call_without_opaque, 146},
  {"lib/request_seal/structured_fields/schema.ex", :call_with_opaque, 147},
  {"lib/request_seal/structured_fields/schema.ex", :call_without_opaque, 147},
  {"lib/finch/request.ex", :unknown_type, 60},
  {"lib/finch/request.ex", :unknown_type, 78},
  {"lib/finch/response.ex", :unknown_type, 16},
  {"lib/finch/response.ex", :unknown_type, 18},
  {"lib/finch/response.ex", :unknown_type, 19},
  {"lib/request_seal/discovery.ex", :call, 629},
  {"lib/request_seal/discovery.ex", :call, 685}
]
