import { Router } from "express";
import {getPublicKeyRSA, createRsaPair, encryptMessage, decrypt, signMessage, verifyMessage, verifyBlind, signBlind} from '../controller/rsaController'


const router = Router();

router.get('/generate', createRsaPair);
router.get('/public', getPublicKeyRSA);
router.post('/encrypt', encryptMessage);
router.post('/decrypt', decrypt)
router.post('/verify', verifyMessage);
router.post('/verifyBlind', verifyBlind);
router.post('/sign', signMessage)
router.post('/signBlind', signBlind)


export default router;


