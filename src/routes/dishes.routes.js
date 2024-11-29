import { Router } from 'express';
import { prisma } from '../db.js';
import { authenticateToken, authorizeAdmin } from './users.routes.js'; // Asegúrate de tener los middlewares adecuados

const router = Router();

// Obtener todos los platos
router.get("/dishes", async (req, res) => {
    try {
        const dishes = await prisma.dish.findMany();
        res.json(dishes);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while fetching dishes' });
    }
});

// Crear un nuevo plato (solo ADMIN)
router.post("/dishes", authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { name, description, price, image } = req.body;

        // Validación de los campos obligatorios
        if (!name || !description || !price || !image) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Asegurarse de que el precio sea un número
        let parsedPrice = parseFloat(price);
        if (isNaN(parsedPrice)) {
            return res.status(400).json({ message: 'Price must be a valid number' });
        }

        // Crear el plato en la base de datos
        await prisma.dish.create({
            data: { name, description, price: parsedPrice, image }
        });

        res.status(201).json({ message: 'Dish created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while creating the dish' });
    }
});

export default router;
