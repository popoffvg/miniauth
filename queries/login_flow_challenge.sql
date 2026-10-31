-- name: SetLoginFlowChallenge :execrows
UPDATE login_flows
SET challenge = sqlc.arg(challenge)
WHERE id = sqlc.arg(id) AND expires_at > now();

-- name: TakeLoginFlowChallenge :one
WITH taken AS (
    SELECT id, challenge
    FROM login_flows
    WHERE login_flows.id = sqlc.arg(id) AND challenge IS NOT NULL AND expires_at > now()
    FOR UPDATE
)
UPDATE login_flows
SET challenge = NULL
FROM taken
WHERE login_flows.id = taken.id
RETURNING taken.challenge::bytea AS challenge;
