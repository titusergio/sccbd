import { Router } from "express";
import {getPublicKeyRSA, createRsaPair, encryptMessage, decrypt, signMessage, verifyMessage, verifyBlind, getBlind} from '../controller/rsaController'


const router = Router();

router.get('/generate', createRsaPair);
router.get('/public', getPublicKeyRSA);
router.post('/encrypt', encryptMessage);
router.post('/decrypt', decrypt)
router.post('/verify', verifyMessage);
router.post('/verifyBlind', verifyBlind);
router.post('/sign', signMessage)
//router.post('/signBlind', signBlind)
router.get('/hash', getBlind)


export default router;


