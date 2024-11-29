import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import dishesRoutes from "./routes/dishes.routes.js";
import usersRoutes from "./routes/users.routes.js";
import https from "https";
import http from "http";
import fs from "fs";

// Variables de entorno
const JWT_SECRET = process.env.JWT_SECRET; 
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const HTTPS_PORT = process.env.HTTPS_PORT || 443; 
const HTTP_PORT = process.env.HTTP_PORT || 80; 
const app = express();

app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(express.json());

// Middleware: Verificar token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
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
  res.json({
    message: "Ruta protegida accesible solo con token válido",
    user: req.user,
  });
});

// Cargar certificados SSL
const sslOptions = {
  key: fs.readFileSync("./ssl/key.pem"),
  cert: fs.readFileSync("./ssl/cert.pem"),
};

// Iniciar servidor HTTPS
https.createServer(sslOptions, app).listen(HTTPS_PORT, "0.0.0.0", () => {
  console.log(`Servidor HTTPS corriendo en el puerto ${HTTPS_PORT}`);
});

// Iniciar servidor HTTP para redirección
http.createServer((req, res) => {
  res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
  res.end();
}).listen(HTTP_PORT, "0.0.0.0", () => {
  console.log(`Servidor HTTP corriendo en el puerto ${HTTP_PORT} y redirigiendo a HTTPS`);
});
