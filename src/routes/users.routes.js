import { Router } from 'express';
import { prisma } from '../db.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt'; // Importa bcrypt

const router = Router();
const JWT_SECRET = 'your_jwt_secret_key';

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

// Middleware: Verificar si es ADMIN
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {  // Asegúrate de que el rol sea 'admin'
    return res.status(403).json({ message: 'Acceso denegado: No eres ADMIN.' });
  }
  next();
};

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ message: 'Usuario no encontrado' });

    // Compara la contraseña usando bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

export { authenticateToken, authorizeAdmin };
export default router;
