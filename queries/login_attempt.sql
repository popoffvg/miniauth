-- name: InsertLoginAttempt :exec
INSERT INTO login_attempts (login, ip, succeeded, attempted_at)
VALUES ($1, $2, $3, $4);

-- name: CountLoginFailures :one
-- A success resets the count for its login. It does not reset the count for its IP.
SELECT
    count(*)::bigint AS failures,
    max(f.attempted_at)::timestamptz AS last_failure
FROM login_attempts AS f
WHERE f.login = sqlc.arg(login)
    AND NOT f.succeeded
    AND f.attempted_at >= sqlc.arg(since)::timestamptz
    AND f.attempted_at > coalesce(
        (
            SELECT max(s.attempted_at)
            FROM login_attempts AS s
            WHERE s.login = sqlc.arg(login) AND s.succeeded
        ),
        '-infinity'::timestamptz
    );

-- name: CountIPFailures :one
SELECT
    count(*)::bigint AS failures,
    max(attempted_at)::timestamptz AS last_failure
FROM login_attempts
WHERE ip = sqlc.arg(ip)
    AND NOT succeeded
    AND attempted_at >= sqlc.arg(since)::timestamptz;

-- name: DeleteLoginAttemptsBefore :exec
DELETE FROM login_attempts
WHERE attempted_at < $1;
