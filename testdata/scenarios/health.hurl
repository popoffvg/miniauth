# The probes and the API description need no session and no token.
GET {{host}}/healthz
HTTP 204

GET {{host}}/readyz
HTTP 200

GET {{host}}/openapi.yaml
HTTP 200
[Asserts]
header "Content-Type" contains "yaml"
body contains "openapi:"
body contains "/auth/check:"
body contains "/api/v1/users:"
