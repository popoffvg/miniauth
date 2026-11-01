# The second half of recovery.hurl. reset_token is the token of the link that the Go runner read from the mail log.
GET {{host}}/recover/{{reset_token}}
HTTP 200
[Asserts]
header "Referrer-Policy" == "no-referrer"
header "Cache-Control" == "no-store"
xpath "string(//input[@name='token']/@value)" == "{{reset_token}}"
xpath "string(//form/@action)" == "/recover/reset"

POST {{host}}/recover/reset
Origin: https://evil.example.test
[Form]
token: {{reset_token}}
password: {{run}}-new
HTTP 403

POST {{host}}/recover/reset
Origin: {{origin}}
[Form]
token: {{reset_token}}
password: {{run}}-new
HTTP 200
[Asserts]
header "Referrer-Policy" == "no-referrer"
body contains "Password changed"

# The link works once.
GET {{host}}/recover/{{reset_token}}
HTTP 400
[Asserts]
body contains "The link is not valid, was used, or expired."

GET {{host}}/login
HTTP 200

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}@example.test
password: {{run}}-old
HTTP 200
[Asserts]
body contains "The login or the password is wrong."

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}@example.test
password: {{run}}-new
HTTP 303
[Asserts]
cookie "__Secure-id_session" exists
