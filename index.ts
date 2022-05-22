import express from 'express';
import * as rsa from './models/rsa'
import rsaRoutes from './routes/rsaRoutes'
import bodyParser from 'body-parser';

const clientA = express();
const clientB = express();

const PORT = 4000;



let RsaPrivateKey:rsa.RsaPrivateKey

clientA.listen(PORT, () => console.log(`Server running on : http://localhost:${PORT}`));
clientA.use(express.json())
clientA.use('/rsa',rsaRoutes);

clientB.listen(4001, () => console.log(`Server running on : http://localhost:${PORT}`));
clientB.use(express.json())
clientB.use('/rsa',rsaRoutes);

               //only looks at requests where the Content-Type header matches the type option.
//app.use(express.urlencoded({ limit: '30mb', extended: true }))            // limito el tamaño, puede q no sea necessario para nuestra aplicacions

//app.use(cors())                       middleware
//app.use(morgan('dev'))                useful logger when app isused in developmen
//mongoose connection?
//socke connection?
