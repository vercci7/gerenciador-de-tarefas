import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// Conexão com MySQL
const db = await mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Middleware para validar token
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Token obrigatório" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Token inválido" });
    req.userId = decoded.id;
    next();
  });
}

// Rota de registro
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  try {
    const [rows] = await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed]);
    res.json({ message: "Usuário registrado", userId: rows.insertId });
  } catch (err) {
    res.status(400).json({ error: "Usuário já existe ou erro no registro" });
  }
});

// Rota de login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);

  if (rows.length === 0) return res.status(400).json({ error: "Usuário não encontrado" });

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Senha incorreta" });

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login bem-sucedido", token });
});

// Criar tarefa
app.post("/tasks", authMiddleware, async (req, res) => {
  const { title, description } = req.body;
  await db.query("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)", [
    req.userId,
    title,
    description,
  ]);
  res.json({ message: "Tarefa criada" });
});

// Listar tarefas
app.get("/tasks", authMiddleware, async (req, res) => {
  const [tasks] = await db.query("SELECT * FROM tasks WHERE user_id = ?", [req.userId]);
  res.json(tasks);
});

// Deletar tarefa
app.delete("/tasks/:id", authMiddleware, async (req, res) => {
  await db.query("DELETE FROM tasks WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
  res.json({ message: "Tarefa deletada" });
});

app.listen(process.env.PORT, () => {
  console.log("Servidor rodando na porta " + process.env.PORT);
});
// Atualizar tarefa (concluir / desmarcar)
app.patch("/tasks/:id", authMiddleware, async (req, res) => {
  const { completed } = req.body;
  const taskId = req.params.id;

  try {
    await db.query(
      "UPDATE tasks SET completed = ? WHERE id = ? AND user_id = ?",
      [completed ? 1 : 0, taskId, req.userId]
    );
    res.json({ message: "Tarefa atualizada" });
  } catch (err) {
    res.status(400).json({ error: "Erro ao atualizar tarefa" });
  }
});
