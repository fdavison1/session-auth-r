CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR,
    password VARCHAR,
    isAdmin BOOL
)