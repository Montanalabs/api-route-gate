#! VULNERABLE api-route-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant routeApi

let raw = fetch<web>
privileged { routeApi(raw) }  # tainted -> tool: REJECTED
