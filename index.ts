import express from 'express';

import * as rsa from './rsa'



const app = express();
const PORT = 4000;

let RsaPrivateKey:rsa.RsaPrivateKey


//app.use(express.json())               only looks at requests where the Content-Type header matches the type option.
//app.use(cors())                       middleware
//app.use(morgan('dev'))                useful logger when app isused in developmen


//mongoose connection?

//socke connection?

app.listen(PORT, () => console.log(`Server running on port: http://localhost:${PORT}`));


let keyPair = rsa.generateKeys(2049)

async function testRsa(number:BigInt){
    
    let keyPair:rsa.rsaKeyPair
    keyPair =  await rsa.generateKeys(2048);
    console.log(keyPair)
}


testRsa(BigInt(2048))
//rsa.testBcu()



/*
const main = async function(){
    const keypair = await generateKeys(bitlength)
    let m:bigint = bcu.randBetween(keypair.publickey.n - 1n)
    const c = keypair.pyblickey.publickey.encrypt(m)
    const d = keypair.privkey.decrypt(c)
    if(m !== d) {
        console.log("ERROR")
    } else {
        console.log("WIN")
    }

    }

main()

*/


