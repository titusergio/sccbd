import { Router } from "express";
import {getPublicKeyRSA, createRsaPair, encryptMessage} from '../controller/rsaController'


const router = Router();

router.get('/generate', createRsaPair);
router.get('/public', getPublicKeyRSA);
router.post('/encrypt', encryptMessage);


export default router;


