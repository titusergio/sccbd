import express from 'express';
import * as rsa from './models/rsa'
import rsaRoutes from './routes/rsaRoutes'
import bodyParser from 'body-parser';

const app = express();
const PORT = 4000;



let RsaPrivateKey:rsa.RsaPrivateKey

app.listen(PORT, () => console.log(`Server running on : http://localhost:${PORT}`));
app.use(express.json())
app.use('/rsa',rsaRoutes);

               //only looks at requests where the Content-Type header matches the type option.
//app.use(express.urlencoded({ limit: '30mb', extended: true }))            // limito el tamaño, puede q no sea necessario para nuestra aplicacions

//app.use(cors())                       middleware
//app.use(morgan('dev'))                useful logger when app isused in developmen
//mongoose connection?
//socke connection?
