# An invite link creates one account with a grant on one resource. The link works once.
POST {{host}}/api/v1/resources
Authorization: Bearer {{admin_token}}
{"name": "{{run}}-wiki", "url": "{{origin}}/{{run}}/wiki"}
HTTP 201

POST {{host}}/api/v1/invites
Authorization: Bearer {{admin_token}}
{"resource": "{{run}}-wiki"}
HTTP 201
[Asserts]
jsonpath "$.resource" == "{{run}}-wiki"
jsonpath "$.link" startsWith "{{origin}}/invite/"
jsonpath "$.expires_at" exists
[Captures]
invite: jsonpath "$.link" regex "/invite/([^/?#]+)$"

GET {{host}}/invite/{{invite}}
HTTP 200
[Asserts]
header "Referrer-Policy" == "no-referrer"
header "Cache-Control" == "no-store"
xpath "string(//input[@name='token']/@value)" == "{{invite}}"
xpath "count(//input[@name='login'])" == 1

POST {{host}}/invite/accept
Origin: https://evil.example.test
[Form]
token: {{invite}}
login: {{run}}-gina
password: {{run}}-secret
HTTP 403

POST {{host}}/invite/accept
Origin: {{origin}}
[Form]
token: {{invite}}
login: {{run}}-gina
password: {{run}}-secret
HTTP 303
[Asserts]
header "Location" == "https://{{public_host}}/{{run}}/wiki"
cookie "__Secure-id_session[HttpOnly]" exists
cookie "__Secure-id_session[Secure]" exists

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/wiki/start
HTTP 200
[Asserts]
header "X-Auth-User" == "{{run}}-gina"

POST {{host}}/invite/accept
Origin: {{origin}}
[Form]
token: {{invite}}
login: {{run}}-hank
password: {{run}}-secret
HTTP 410
[Asserts]
body contains "This invite link does not work."

GET {{host}}/invite/{{invite}}
HTTP 410
