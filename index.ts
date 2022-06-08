import express from 'express';
import rsaRoutes from './routes/rsaRoutes'
import paillierRoutes from './routes/paillierRoutes'

const clientA = express();
const PORT = 4001;

clientA.listen(PORT, () => console.log(`Server running on : http://localhost:${PORT}`));
clientA.use(express.json())
clientA.use('/rsa',rsaRoutes);
clientA.use('/paillier',paillierRoutes);