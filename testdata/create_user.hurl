POST {{host}}/api/v1/users
Authorization: Bearer {{token}}
Content-Type: application/json
{
  "login": "{{login}}",
  "password": "{{password}}"
}
HTTP 201
[Asserts]
jsonpath "$.login" == "{{login}}"
jsonpath "$.id" exists

POST {{host}}/api/v1/users
Authorization: Bearer {{token}}
Content-Type: application/json
{
  "login": "{{login}}",
  "password": "{{password}}"
}
HTTP 409

POST {{host}}/api/v1/users
Content-Type: application/json
{
  "login": "{{login}}",
  "password": "{{password}}"
}
HTTP 401
