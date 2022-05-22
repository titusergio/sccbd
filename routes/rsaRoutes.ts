import { Router } from "express";
import {getPublicKeyRSA, createRsaPair, encryptMessage, decryptMessage, signMessage, verifyMessage} from '../controller/rsaController'


const router = Router();

router.get('/generate', createRsaPair);
router.get('/public', getPublicKeyRSA);
router.post('/encrypt', encryptMessage);
router.post('/verify', verifyMessage);
router.post('/sign', signMessage )
router.post('/decrypt', decryptMessage)


export default router;


