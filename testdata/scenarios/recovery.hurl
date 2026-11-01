# A user whose login is an email address asks for a reset link.
# The image runs with MINIAUTH_MAIL=log. The Go runner reads the link from the log and runs recovery_reset.hurl.
POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
{"login": "{{run}}@example.test", "password": "{{run}}-old"}
HTTP 201

GET {{host}}/login
HTTP 200
[Asserts]
xpath "count(//a[@href='/recover'])" == 1

GET {{host}}/recover
HTTP 200
[Asserts]
xpath "count(//form[@method='post']//input[@name='email'])" == 1

POST {{host}}/recover
Origin: https://evil.example.test
[Form]
email: {{run}}@example.test
HTTP 403

# A known and an unknown address get the same page.
POST {{host}}/recover
Origin: {{origin}}
[Form]
email: {{run}}-unknown@example.test
HTTP 200
[Asserts]
body contains "If the address is known, a link is on its way."

POST {{host}}/recover
Origin: {{origin}}
[Form]
email: {{run}}@example.test
HTTP 200
[Asserts]
body contains "If the address is known, a link is on its way."
