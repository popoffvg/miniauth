# An imported personal access token works as a Bearer token inside its scope only.
# A token is idp_ and 43 base62 characters. The run id makes it unique.
POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
[Options]
variable: pat=idp_{{run}}0000000000000000000000000000000
{"login": "{{run}}-erin", "password": "{{run}}-secret"}
HTTP 201

POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
{"login": "{{run}}-frank", "password": "{{run}}-secret"}
HTTP 201

POST {{host}}/api/v1/resources
Authorization: Bearer {{admin_token}}
{"name": "{{run}}-site", "url": "{{origin}}/{{run}}"}
HTTP 201

POST {{host}}/api/v1/grants
Authorization: Bearer {{admin_token}}
{"resource": "{{run}}-site", "user": "{{run}}-erin"}
HTTP 201

POST {{host}}/api/v1/tokens/import
Authorization: Bearer {{admin_token}}
{"user": "{{run}}-erin", "name": "mcp client", "scopes": ["{{origin}}/{{run}}/mcp"], "token": "{{pat}}"}
HTTP 201
[Asserts]
jsonpath "$.id" exists
jsonpath "$.name" == "mcp client"
jsonpath "$.prefix" matches "^idp_[a-z0-9]{4}$"
body not contains "{{pat}}"

GET {{host}}/auth/check
Authorization: Bearer {{pat}}
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/mcp/tools
HTTP 200
[Asserts]
header "X-Auth-User" == "{{run}}-erin"
header "X-Auth-Method" == "token"

# The user has a grant for the whole site, but the token scope is /mcp only.
GET {{host}}/auth/check
Authorization: Bearer {{pat}}
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/web
HTTP 403
[Asserts]
header "X-Auth-User" not exists

GET {{host}}/auth/check
Authorization: Bearer idp_{{run}}1111111111111111111111111111111
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/mcp/tools
HTTP 401
[Asserts]
header "WWW-Authenticate" == "Bearer error=\"invalid_token\""

POST {{host}}/api/v1/tokens/import
Authorization: Bearer {{admin_token}}
{"user": "{{run}}-erin", "name": "mcp client", "scopes": ["{{origin}}/{{run}}/mcp"], "token": "{{pat}}"}
HTTP 200

POST {{host}}/api/v1/tokens/import
Authorization: Bearer {{admin_token}}
{"user": "{{run}}-frank", "name": "mcp client", "scopes": ["{{origin}}/{{run}}/mcp"], "token": "{{pat}}"}
HTTP 409
[Asserts]
header "Content-Type" == "application/problem+json"
body not contains "{{pat}}"
