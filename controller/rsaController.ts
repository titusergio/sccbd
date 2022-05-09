import { Request,Response } from 'express';
import * as bc from "bigint-conversion";
import * as rsa from '../models/rsa'


let keyPair:rsa.rsaKeyPair


//generate RSA key pair
export async function createRsaPair(req: Request, res: Response){ 
    
    console.log("**********Generating RSA keys**********")
    keyPair = await rsa.generateKeys(2049)
    if(!keyPair){
      res.status(500).send("Internal error, keys haven't been created");
      return;
    }
    console.log("Key pair generated = ", keyPair)
    res.status(200).send("Key pair creared succesfully!");
  }

export async function getPublicKeyRSA(req: Request, res: Response) {

  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }  

  try {
       let data = {
        e: bc.bigintToHex(keyPair.publicKey.e),
        n: bc.bigintToHex(keyPair.publicKey.n),
        j: keyPair.publicKey.e.toString(16)
      }; 
      console.log("Sending public key")
      res.status(200).send(data);
    } catch (err) {
      res.status(500).json({ message: "Server error" });
      console.log("Internal error ocurred: ", err)
    }
  }



export async function encryptMessage (req: Request, res: Response) {

  
  const message:string = req.body.message;
  const m:bigint=BigInt(message)

  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
    
  }

  try {
       let data = {
        encrypted_message: keyPair.publicKey.encrypt(m).toString(),
      }; 
      console.log("Sending encrypted message")
      res.status(200).send(data);
    } catch (err) {
      res.status(500).json({ message: "Server error" });
      console.log("Internal error ocurred: ", err)
    }
  }
