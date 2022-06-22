import * as rsa from './models/rsa'
import * as paillier from './models/paillier'
import * as bcu from 'bigint-crypto-utils'
import * as bc from "bigint-conversion";
import axios from 'axios';

import { split, combine } from 'shamirs-secret-sharing-ts'



async function testApp() {

let pubK : rsa.RsaPublicKey | undefined

let keyPair : rsa.rsaKeyPair

    type publicKey= {
        e : string, 
        n : string
    }

    type encryptResponse = {
      encrypted_message : string
  }
    
    type decryptResponse = {
        decrypted_message : string
    }

    type signedResponse = {
      signed_message : string
    

    }

    type addOperation = {
      solution : string
  }
   

    
 
    
    
    async function encryptMessage(m : bigint) {

        try {

        const response = await axios.get<publicKey>("http://localhost:4002/rsa/public", {
            headers: {
              Accept: 'application/json',
            },
          },
        );

        const receiverPublicKey =  new rsa.RsaPublicKey( bc.hexToBigint(response.data.e),(bc.hexToBigint(response.data.n)))
        pubK = receiverPublicKey
        const encryptedMessage: bigint =  receiverPublicKey.encrypt(m)
        console.log("encrypted : ", encryptedMessage)

        const decryptResponse = await axios.post<decryptResponse>(
            "http://localhost:4002/rsa/decrypt",
            { message: bc.bigintToHex(encryptedMessage) },
            {
              headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
              },
            },
          );

          const decryptedMessage = bc.hexToBigint(decryptResponse.data.decrypted_message)
          console.log("decrypted response : ", decryptedMessage)
          if (decryptedMessage == m ){
            console.log("Correct decryption")
          }

        //console.log("public key ", response.data.e )
        
    }catch(err){
        console.log("error", err)
    }
}

async function blindMessage(m : bigint) {
  try {

    const response = await axios.get<publicKey>("http://localhost:4002/rsa/public", {
        headers: {
          Accept: 'application/json',
        },
      },
    );

    const receiverPublicKey =  new rsa.RsaPublicKey( bc.hexToBigint(response.data.e),(bc.hexToBigint(response.data.n)))

  const  blindFactor = bcu.randBetween(100000n,1n)

  let blindMessage: bigint | undefined = receiverPublicKey.blind(m,blindFactor)
  

  //console.log("Blind message: ", blindMessage)
  if(blindMessage == undefined) return
  

  const signResponse = await axios.post<signedResponse>(
      "http://localhost:4002/rsa/signBlind",
      { message: bc.bigintToHex(blindMessage) },
      {
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      },
    );

    const signedMessage = bc.hexToBigint(signResponse.data.signed_message)

    const unblind = receiverPublicKey.unblind(signedMessage, blindFactor)

    const verifiedMessage = receiverPublicKey.verify(unblind)

    console.log("verified message ", verifiedMessage)

    

  //console.log("public key ", response.data.e )
  
}catch(err){
  console.log("error", err)
}
}

async function testPaillier(transactionA : bigint,transactionB : bigint) {


  try {

    const responseGenerate =await axios.get<String>("http://localhost:4002/paillier/generate", {
        headers: {
          Accept: 'application/json',
        },
      },
    );

    console.log(responseGenerate.data)

    const transAEncrypted = await axios.post<encryptResponse>(
      "http://localhost:4002/paillier/encrypt",
      { message: bc.bigintToHex(transactionA) },
      {
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      },
    );

    const transBEncrypted = await axios.post<encryptResponse>(
      "http://localhost:4002/paillier/encrypt",
      { message: bc.bigintToHex(transactionB) },
      {
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      },
    );

    const addedValue = await axios.post<addOperation>(
      "http://localhost:4002/paillier/add",
      { transA:transAEncrypted.data.encrypted_message,
        transB:transBEncrypted.data.encrypted_message
       },
      {
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      },
    );

    
    

    
    const decryptTrans = await axios.post<decryptResponse>(
      "http://localhost:4002/paillier/decrypt",
      { message:addedValue.data.solution },
      {
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      },
    );

    console.log("decrypt paillier response: ", bc.hexToBigint(decryptTrans.data.decrypted_message))

    




    
  
}catch(err){
  console.log("error", err)
}
}

keyPair = await  rsa.generateKeys(2049)
encryptMessage(22222n)
blindMessage(111111111n)
testPaillier(10n, 5n)

/*
    
    

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
    let blindMess: bigint | undefined = Bank.keys.publicKey.blind(Alice.message, Alice.blindFactor)
    //console.log("Blind message: ", blindMessage)
    if(blindMess == undefined) return 

    //Alice ask the bank to sign the blind message
    let signedBlindMessage :  bigint = Bank.keys.privateKey.sign(blindMess)
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

    */



    


    
}

testApp()


