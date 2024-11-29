import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import dishesRoutes from "./routes/dishes.routes.js";
import usersRoutes from "./routes/users.routes.js";

const app = express();
const JWT_SECRET = 'your_jwt_secret_key';

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));

app.use(express.json());

// Middleware: Verificar token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Rutas
app.use("/api", dishesRoutes);
app.use("/api", usersRoutes);

// Ruta protegida de prueba
app.get("/api/protected-route", authenticateToken, (req, res) => {
  res.json({ message: "Ruta protegida accesible solo con token válido", user: req.user });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
