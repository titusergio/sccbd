import * as rsa from './models/rsa'
import * as paillier from './models/paillier'
import * as bcu from 'bigint-crypto-utils'
import * as bc from "bigint-conversion";
import { split, combine } from 'shamirs-secret-sharing-ts'


async function testApp() { 

    const Bank = {
        keys : await rsa.generateKeys(2049)
    }

    const Alice = {
        keys : await rsa.generateKeys(2049),
        blindFactor : bcu.randBetween(100000n,1n), 
        message : bc.textToBigint("Message to blind"),
        paillierKeys : await paillier.generatePaillierKeys(),
        balance1 : 10n,
        balance2 : 5n
    }
    



    //*****************RSA**************************

    //ENCRYPTION TEST: Alice wants to send encrypted message to the bank, so only Bank chan see the messagle in the clear
    const encryptedMessage = Bank.keys.publicKey.encrypt(Alice.message)
    //console.log("Encrypted message: ", encryptedMessage)

    const decryptedMessage = Bank.keys.privateKey.decrypt(encryptedMessage)
    //console.log("Decrypted message: ", decryptedMessage)

    if(Alice.message == decryptedMessage) console.log("The message has been successfully encrypted and decrypted")



    //BLIND SIGNATURE TEST : Alice want to get her message signed by Bank, but she doesn't want Bank to see the message
    //Alice knows the Bank public key, so she used it to blind the message
    let blindMessage: bigint | undefined = Bank.keys.publicKey.blind(Alice.message, Alice.blindFactor)
    //console.log("Blind message: ", blindMessage)
    if(blindMessage == undefined) return 

    //Alice ask the bank to sign the blind message
    let signedBlindMessage :  bigint = Bank.keys.privateKey.sign(blindMessage)
    //console.log("Signed blind message: ", signedBlindMessage)

    //Alice use the blind factor to unblind the signature
    let unblindSign : bigint = Bank.keys.publicKey.unblind(signedBlindMessage,Alice.blindFactor)
    //console.log("Unblind signed message: ", unblindSign)

    let checkedSigned = Bank.keys.publicKey.verify(unblindSign)
    //console.log("Checked signed: ", checkedSigned)

    if(checkedSigned == Alice.message ) console.log("The blind message has been verified")








    //******************SHARED KEY**************************
    //Alice doesn't want to keep her private key on her computer and decides to share it with her trusted friends, so if her computer ever crashes, Alice can retrieve her private key.
    
    const shares = split(String(Alice.keys.privateKey.d), { shares: 5, threshold: 3 })
    const friend1 = shares[0] 
    const friend2 = shares[3] 
    const friend3 = shares[4]
    
    const recovered = combine([friend1,friend2,friend3])
    if ( String(Alice.keys.privateKey.d) === String(recovered) ){
        console.log("Private key recovered!!")
    }









    //******************PAILLIER******************************
    //Alice now wants the bank to add two of ther balances, but she needs to send that information encrypted and doesn't want the
    //bank decrypt it, so she uses homomorphic encryption

    const balance1Encrypted : bigint = Alice.paillierKeys.publicKey.encrypt(Alice.balance1)
    const balance2Encrypted : bigint = Alice.paillierKeys.publicKey.encrypt(Alice.balance2)

    const bankSumOperation : bigint = Alice.paillierKeys.publicKey.addition(balance1Encrypted,balance2Encrypted)
    const aliceCheckOperation = Alice.paillierKeys.privateKey.decrypt(bankSumOperation)
    //console.log("decrypt balance 1: ", Alice.paillierKeys.privateKey.decrypt(balance1Encrypted))
    //console.log("alice check: ", aliceCheckOperation)
    if ( aliceCheckOperation == (Alice.balance1 + Alice.balance2)) console.log("Homomorphic operation was successful")


    
}

testApp()


