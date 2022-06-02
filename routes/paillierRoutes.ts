import { Router } from "express";
import { encrypt, decrypt, generatePaillierKeys} from '../controller/paillierController'


const router = Router();

router.get('/generate', generatePaillierKeys);
router.post('/encrypt', encrypt);
router.post('/decrypt', decrypt)


export default router;