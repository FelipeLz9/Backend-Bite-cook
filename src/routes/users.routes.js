import { Router } from 'express';
import { prisma } from '../db.js';
import bcrypt from 'bcrypt'; // Para hashear y comparar contraseñas
import jwt from 'jsonwebtoken'; // Para generar y verificar tokens JWT

const router = Router();

// Clave secreta para firmar y verificar el JWT
const JWT_SECRET = 'your_jwt_secret_key';  // Cambia esto por una clave segura

// Middleware para verificar el token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);  // No hay token, retorna 401 (No autorizado)

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);  // Token no válido, retorna 403 (Prohibido)
        
        req.user = user;  // El token es válido, guarda el usuario en la request
        next();  // Continúa a la siguiente función en la ruta
    });
};

// Ruta para iniciar sesión (login)
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Verificar si el usuario existe en la base de datos
        const user = await prisma.user.findUnique({
            where: { email }
        });

        if (!user) {
            return res.status(401).json({ message: 'Usuario no encontrado' });
        }

        // Comparar la contraseña ingresada con la almacenada en la base de datos
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        // Generar un token JWT
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
            expiresIn: '1h',
        });

        // Retornar el token al frontend
        res.json({ token });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error al iniciar sesión' });
    }
});

// Ruta pública - Obtener todos los usuarios
router.get("/users", async (req, res) => {
    try {
        const users = await prisma.user.findMany();
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener usuarios' });
    }
});

// Ruta protegida - Solo usuarios autenticados pueden acceder
router.get("/users/me", authenticateToken, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.userId }
        });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener usuario' });
    }
});

// Ruta para registrar usuario (no protegida)
router.post("/users", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Verificar si el usuario ya existe
        const existingUser = await prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            return res.status(400).json({ message: 'El correo electrónico ya está en uso.' });
        }

        // Hashear la contraseña antes de guardarla en la base de datos
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,  // Guardar la contraseña hasheada
            },
        });

        res.status(201).json(newUser);
    } catch (error) {
        console.error('Error al crear el usuario:', error);
        res.status(500).json({ message: 'Error al crear el usuario' });
    }
    // Actualizar datos del usuario autenticado
router.put("/users/me", authenticateToken, async (req, res) => {
    const { name, email, password } = req.body;
  
    try {
      const updatedUserData = {
        name,
        email,
      };
  
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updatedUserData.password = hashedPassword;
      }
  
      const updatedUser = await prisma.user.update({
        where: { id: req.user.userId },
        data: updatedUserData,
      });
  
      res.json(updatedUser);
    } catch (error) {
      console.error('Error updating user:', error);
      res.status(500).json({ message: 'Error al actualizar el usuario' });
    }
  });
  
});

export default router;
