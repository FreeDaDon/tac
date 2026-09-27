# one query per line
SELECT id, name FROM users WHERE id = ?
SELECT name FROM products UNION SELECT name FROM archived_products
SELECT * FROM users WHERE name = '' UNION SELECT username, password FROM admins --'
SELECT * FROM items WHERE id = 1 UNION ALL SELECT NULL, NULL, NULL
SELECT * FROM users WHERE name = 'x' OR '1'='1'
DROP TABLE users
