-- ============================================================
-- BD Simulator - Seed Data
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price NUMERIC(10,2),
    stock INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    product_id INT REFERENCES products(id),
    quantity INT DEFAULT 1,
    total NUMERIC(10,2),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action TEXT,
    actor VARCHAR(50),
    ts TIMESTAMP DEFAULT NOW()
);

-- Seed users (passwords are bcrypt hashes of 'password123')
INSERT INTO users (username, password_hash, email, role) VALUES
    ('admin',   '$2b$12$KIXlP2z1HkD3Qm9cV7aLleX8yZ1vR4wNpQmS2tU6oK3jL9dN5hW8a', 'admin@corp.local',   'admin'),
    ('alice',   '$2b$12$MnO3pQ4rS5tU6vW7xY8zA9bC0dE1fG2hI3jK4lM5nO6pQ7rS8tU9v', 'alice@corp.local',   'user'),
    ('bob',     '$2b$12$AbC1dE2fG3hI4jK5lM6nO7pQ8rS9tU0vW1xY2zA3bC4dE5fG6hI7jK', 'bob@corp.local',     'user'),
    ('charlie', '$2b$12$XyZ9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT9uV8wX7yZ6aB5cD4eF3g', 'charlie@corp.local', 'manager')
ON CONFLICT DO NOTHING;

-- Seed products
INSERT INTO products (name, price, stock) VALUES
    ('Laptop Pro X',   1299.99, 15),
    ('Wireless Mouse', 29.99,   80),
    ('USB Hub 7-port', 49.99,   45),
    ('Mechanical KB',  89.99,   30)
ON CONFLICT DO NOTHING;

-- Seed orders
INSERT INTO orders (user_id, product_id, quantity, total) VALUES
    (2, 1, 1, 1299.99),
    (3, 2, 2, 59.98),
    (2, 3, 1, 49.99),
    (4, 4, 1, 89.99)
ON CONFLICT DO NOTHING;

-- Low-priv app role
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_readonly') THEN
        CREATE ROLE app_readonly;
    END IF;
END $$;

GRANT SELECT ON users, products, orders TO app_readonly;
