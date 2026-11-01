# The users admin API changes groups and the disabled state. A disabled user loses each session.
GET {{host}}/healthz
[Options]
variable: group=admin
HTTP 204

POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
{"login": "{{run}}-ivy", "password": "{{run}}-secret"}
HTTP 201

POST {{host}}/api/v1/resources
Authorization: Bearer {{admin_token}}
{"name": "{{run}}-ops", "url": "{{origin}}/{{run}}/ops"}
HTTP 201

POST {{host}}/api/v1/grants
Authorization: Bearer {{admin_token}}
{"resource": "{{run}}-ops", "user": "{{run}}-ivy"}
HTTP 201

GET {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
HTTP 200
[Asserts]
jsonpath "$.users[?(@.login == '{{run}}-ivy')]" count == 1

GET {{host}}/api/v1/users
HTTP 401

GET {{host}}/login
HTTP 200

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}-ivy
password: {{run}}-secret
HTTP 303

GET {{host}}/auth/check?group={{group}}
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/ops
HTTP 403

PUT {{host}}/api/v1/groups/{{group}}/members/{{run}}-ivy
Authorization: Bearer {{admin_token}}
HTTP 204

# The add is idempotent.
PUT {{host}}/api/v1/groups/{{group}}/members/{{run}}-ivy
Authorization: Bearer {{admin_token}}
HTTP 204

GET {{host}}/auth/check?group={{group}}
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/ops
HTTP 200
[Asserts]
header "X-Auth-User" == "{{run}}-ivy"
header "X-Auth-Groups" == "{{group}}"

GET {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
HTTP 200
[Asserts]
jsonpath "$.users[?(@.login == '{{run}}-ivy')].groups[0]" contains "{{group}}"

POST {{host}}/api/v1/users/{{run}}-ivy/disable
Authorization: Bearer {{admin_token}}
HTTP 204

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/ops
HTTP 401

# A disabled user cannot sign in again.
GET {{host}}/login
HTTP 200

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}-ivy
password: {{run}}-secret
HTTP 200
[Asserts]
cookie "__Secure-id_session" not exists

POST {{host}}/api/v1/users/{{run}}-ivy/enable
Authorization: Bearer {{admin_token}}
HTTP 204

GET {{host}}/login
HTTP 200

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}-ivy
password: {{run}}-secret
HTTP 303

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/ops
HTTP 200

DELETE {{host}}/api/v1/groups/{{group}}/members/{{run}}-ivy
Authorization: Bearer {{admin_token}}
HTTP 204

DELETE {{host}}/api/v1/groups/{{group}}/members/{{run}}-ivy
Authorization: Bearer {{admin_token}}
HTTP 404
[Asserts]
header "Content-Type" == "application/problem+json"

POST {{host}}/api/v1/users/{{run}}-nobody/disable
Authorization: Bearer {{admin_token}}
HTTP 404
