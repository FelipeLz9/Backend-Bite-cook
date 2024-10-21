// index.js (backend)

import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken"; // Importar jsonwebtoken
import dishesRoutes from "./routes/dishes.routes.js";
import usersRoutes from "./routes/users.routes.js";

const app = express();

app.use(cors({
    origin: 'http://localhost:3000', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json());

const JWT_SECRET = 'your_jwt_secret_key';  // Definir la clave secreta

// Middleware para verificar el token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];  // El token viene en formato 'Bearer <token>'

    if (!token) return res.sendStatus(401);  // Si no hay token, no autorizado

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);  // Si el token no es válido

        req.user = user;  // Guardamos la información del usuario en `req.user`
        next();  // El token es válido, continúa con la petición
    });
};

// Uso de rutas
app.use("/api", dishesRoutes);
app.use("/api", usersRoutes);

// Ruta protegida de ejemplo
app.get("/api/protected-route", authenticateToken, (req, res) => {
    res.json({ message: "Ruta protegida accesible solo con token válido", user: req.user });
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
