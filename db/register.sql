INSERT INTO users (email, password, isadmin)
VALUES ($1, $2, $3)
RETURNING *;

