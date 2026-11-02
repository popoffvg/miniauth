-- name: SetLoginFlowStepState :execrows
UPDATE login_flows
SET step_state = sqlc.arg(step_state)
WHERE id = sqlc.arg(id) AND expires_at > now();

-- name: GetLoginFlowStepState :one
SELECT step_state
FROM login_flows
WHERE id = $1 AND expires_at > now();

-- name: MoveLoginFlowStepState :execrows
UPDATE login_flows
SET step_state = sqlc.arg(next_state)
WHERE id = sqlc.arg(id) AND step_state = sqlc.arg(prev_state) AND expires_at > now();
