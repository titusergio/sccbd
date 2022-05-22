import express from 'express';
import * as rsa from './models/rsa'
import rsaRoutes from './routes/rsaRoutes'
import bodyParser from 'body-parser';

const clientA = express();

const PORT = 4001;


clientA.listen(PORT, () => console.log(`Server running on : http://localhost:${PORT}`));
clientA.use(express.json())
clientA.use('/rsa',rsaRoutes);