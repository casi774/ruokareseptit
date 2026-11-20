CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
);
CREATE TABLE recipes (
    recipe_id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    instructions TEXT,
    category TEXT,
    diets TEXT,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
);