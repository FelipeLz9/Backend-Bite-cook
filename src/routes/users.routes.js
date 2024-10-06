import { Router} from 'express';
import { prisma} from '../db.js';

const router = Router();

router.get("/users", async (req, res) => {
    const users = await prisma.user.findMany()
    res.json(users)
});

router.post("/users", async (req, res) => {
    const newUser = await prisma.user.create({
        data: req.body
    });
    res.json(newUser)
});

export default router;