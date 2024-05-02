const AppError = require("../utils/AppError");
const sqliteConnection = require("../database/sqlite");
const { hash, compare } = require("bcryptjs");

class UsersController {
  async create(request, response) {
    const { name, email, password } = request.body;

    const database = await sqliteConnection();
    const checkIfUserExists = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    );

    if (checkIfUserExists) {
      throw new AppError("E-mail já cadastrado.");
    }

    const hashedPassword = await hash(password, 8);

    await database.run(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );
    return response.json();
  }

  async update(request, response) {
    const { name, email, password, current_password } = request.body;
    const { id } = request.params;
    const database = await sqliteConnection();

    const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);
    if (!user) {
      throw new AppError("Usuário não encontrado.");
    }

    const userWithUpdatedEmail = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    );
    if (userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id) {
      throw new AppError("E-mail já está em uso.");
    }

    if (password && !current_password) {
      throw new AppError("Por favor, informe a senha atual.");
    }

    if (password && current_password) {
      const passwordsMatches = await compare(current_password, user.password);

      if (!passwordsMatches) {
        throw new AppError("Senha atual não confere.");
      }
      user.password = await hash(password, 8);
    }

    user.name = name ?? user.name;
    user.email = email ?? user.email;

    await database.run(
      `
      UPDATE users SET
      name = ?,
      email = ?,
      password = ?,
      updated_at = DATETIME('now')
      WHERE id = ?`,
      [user.name, user.email, user.password, id]
    );

    return response.json();
  }
}

module.exports = UsersController;
