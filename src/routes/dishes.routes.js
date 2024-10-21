import { Router } from 'express';
import { prisma } from '../db.js';

const router = Router();

router.get("/dishes", async (req, res) => {
    const dishes = await prisma.dish.findMany()
    res.json(dishes)
});

router.get("/dishes/:id", async (req, res) => {
    const { id } = req.params;
    const dish = await prisma.dish.findUnique({
        where: {
            id: id
        }
    });
    res.json(dish);
});

router.post("/dishes", async (req, res) => {
    try {
        let { price, ...rest } = req.body;
        if (typeof price === 'string') {
            price = parseFloat(price);
        }
        await prisma.dish.create({
            data: { price, ...rest }
        });
        res.status(201).json({ message: 'Dish created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while creating the dish' });
    }
});

export default router;