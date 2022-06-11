import * as rsa from './models/rsa'
import * as bc from "bigint-conversion";
import { RsaPrivateKey } from "./models/rsa";
import {rsaKeyPair} from './models/rsa'
import { KeyPair } from 'paillier-bigint';



async function testApp() { 



    
    const Alice = {
        keys : await rsa.generateKeys(2049),
        message : 3n,
        blindFactor : 2n
    }

    const Bob = {
        keys : await rsa.generateKeys(2049)
    }


    /*
    let messageToSign : bigint = 123456n

    let signed : bigint = Bob.keys.privateKey.sign(messageToSign)
    console.log("signed: ",signed)
    let verified : bigint = Bob.keys.publicKey.verify(signed)
    console.log("unsgined : ", verified)
    */


    //Alice want to get her message signed by Bob, but she doesn't want Bob to see the message

    console.log("Original messgae : ", Alice.message)

    let blindMessage: bigint = Alice.keys.publicKey.blind(Alice.message, Alice.blindFactor)
    console.log("Blind message: ", blindMessage)
    let signedBlindMessage :  bigint = Bob.keys.privateKey.sign(blindMessage)
    console.log("Signed blind message: ", signedBlindMessage)
    let unblindSign : bigint = Alice.keys.publicKey.unblind(signedBlindMessage,Alice.blindFactor)
    console.log("Unblind signed message: ", unblindSign)

    let checkedBobSigned = Bob.keys.publicKey.verify(unblindSign)
    console.log("Checked bob signed: ", checkedBobSigned)


    /*
    let messageSigned : bigint = Bob.keys.privateKey.sign(Alice.message)
    if(Alice.message== Bob.keys.publicKey.verify(messageSigned)){
        console.log("verified")
    }else console.log("not verified")
    */
   
    
}

testApp()


