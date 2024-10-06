import express from "express";
import dishesRoutes from "./routes/dishes.routes.js";
import usersRoutes from "./routes/users.routes.js";

const app = express();

app.use(express.json());

app.use("/api", dishesRoutes);
app.use("/api", usersRoutes);

app.listen(3000)
console.log("Server is running on port "+ 3000);