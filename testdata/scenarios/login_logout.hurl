# A password login lands on the return URL with a session. A logout ends that session.
# The cookie domain is empty, so the return URL and each protected URL MUST be on the public host.
POST {{host}}/api/v1/users
Authorization: Bearer {{admin_token}}
{"login": "{{run}}-alice", "password": "{{run}}-secret"}
HTTP 201

POST {{host}}/api/v1/resources
Authorization: Bearer {{admin_token}}
{"name": "{{run}}-app", "url": "{{origin}}/{{run}}"}
HTTP 201

POST {{host}}/api/v1/grants
Authorization: Bearer {{admin_token}}
{"resource": "{{run}}-app", "user": "{{run}}-alice"}
HTTP 201

# The login page puts the flow in a cookie, never in the URL.
GET {{host}}/login
[Query]
return: {{origin}}/tokens
HTTP 200
[Asserts]
header "Content-Type" contains "text/html"
cookie "__Host-id_login_flow" exists
cookie "__Host-id_login_flow[HttpOnly]" exists
cookie "__Host-id_login_flow[Secure]" exists
cookie "__Host-id_login_flow[SameSite]" == "Lax"
xpath "count(//form[@method='post']//input[@name='login'])" == 1
xpath "count(//form[@method='post']//input[@name='password'])" == 1

# A POST from another origin is refused.
POST {{host}}/login
Origin: https://evil.example.test
[Form]
login: {{run}}-alice
password: {{run}}-secret
HTTP 403
[Asserts]
cookie "__Secure-id_session" not exists

# A wrong password shows the form again and starts no session.
POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}-alice
password: {{run}}-wrong
HTTP 200
[Asserts]
body contains "The login or the password is wrong."
xpath "count(//input[@name='password'])" == 1
cookie "__Secure-id_session" not exists

GET {{host}}/login
[Query]
return: {{origin}}/tokens
HTTP 200

POST {{host}}/login
Origin: {{origin}}
[Form]
login: {{run}}-alice
password: {{run}}-secret
HTTP 303
[Asserts]
header "Location" == "{{origin}}/tokens"
cookie "__Secure-id_session[HttpOnly]" exists
cookie "__Secure-id_session[Secure]" exists
cookie "__Secure-id_session[SameSite]" == "Lax"
cookie "__Secure-id_session[Path]" == "/"
cookie "__Secure-id_session[Domain]" not exists
cookie "__Secure-id_device[HttpOnly]" exists
[Captures]
session: cookie "__Secure-id_session"

GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/dash?tab=1
HTTP 200
[Asserts]
header "X-Auth-User" == "{{run}}-alice"
header "X-Auth-Method" == "password"
header "X-Auth-Email" == ""

# A browser form gets the login page. Any other client gets 204.
POST {{host}}/logout
Origin: {{origin}}
HTTP 204

# The jar dropped the cookie. The old cookie value is refused too: the session row is gone.
GET {{host}}/auth/check
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/dash
HTTP 401
[Asserts]
header "WWW-Authenticate" == "Bearer"

GET {{host}}/auth/check
Cookie: __Secure-id_session={{session}}
Accept: text/html
X-Forwarded-Proto: https
X-Forwarded-Host: {{public_host}}
X-Forwarded-Uri: /{{run}}/dash
HTTP 302
[Asserts]
header "Location" startsWith "{{origin}}/login"
header "X-Auth-User" not exists
