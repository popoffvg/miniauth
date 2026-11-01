# A grant opens one URL prefix for one user. A revoke applies to the next check.
# The cookie domain is empty, so each protected URL MUST be on the public host.
POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
{"login": "{{run}}-dave", "password": "{{run}}-secret"}
HTTP 201

POST {{host}}/api/v1/resources
Authorization: Bearer {{admin_token}}
{"name": "{{run}}-dash", "url": "{{origin}}/{{run}}/dash"}
HTTP 201
[Asserts]
jsonpath "$.name" == "{{run}}-dash"
jsonpath "$.url" == "{{public_host}}/{{run}}/dash"

POST {{host}}/api/v1/grants
Authorization: Bearer {{admin_token}}
{"resource": "{{run}}-dash", "user": "{{run}}-dave"}
HTTP 201
[Captures]
grant_id: jsonpath "$.id"

GET {{host}}/api/v1/grants
Authorization: Bearer {{admin_token}}
[Query]
user: {{run}}-dave
HTTP 200
[Asserts]
jsonpath "$.grants" count == 1
jsonpath "$.grants[0].id" == "{{grant_id}}"
jsonpath "$.grants[0].resource.name" == "{{run}}-dash"

GET {{host}}/login
HTTP 200

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}-dave
password: {{run}}-secret
HTTP 303

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/dash/panel?id=7
HTTP 200
[Asserts]
header "X-Auth-User" == "{{run}}-dave"

# A prefix ends on a segment border: /dash does not cover /dashx.
GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/dashx
HTTP 403
[Asserts]
header "Content-Type" == "application/problem+json"
jsonpath "$.detail" contains "{{run}}-dave"
header "X-Auth-User" not exists

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/other
HTTP 403

# A browser gets the denial as a page that no cache keeps.
GET {{host}}/auth/check
Accept: text/html
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/other?secret=1
HTTP 403
[Asserts]
header "Cache-Control" == "no-store"
body contains "/{{run}}/other"
body not contains "secret=1"

DELETE {{host}}/api/v1/grants/{{grant_id}}
Authorization: Bearer {{admin_token}}
HTTP 204

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/dash/panel
HTTP 403
