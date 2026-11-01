# The admin API creates a user once. A second create is a conflict, and a call with no admin token is refused.
POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "login": "{{run}}-new",
  "password": "{{run}}-secret"
}
HTTP 201
[Asserts]
jsonpath "$.login" == "{{run}}-new"
jsonpath "$.id" exists

POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "login": "{{run}}-new",
  "password": "{{run}}-secret"
}
HTTP 409
[Asserts]
header "Content-Type" == "application/problem+json"

POST {{host}}/api/v1/users
Content-Type: application/json
{
  "login": "{{run}}-new",
  "password": "{{run}}-secret"
}
HTTP 401
