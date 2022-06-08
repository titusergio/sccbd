import { Request,Response } from 'express';
import * as bc from "bigint-conversion";
import * as rsa from '../models/rsa'
import { modInv } from 'bigint-crypto-utils';

let keyPair:rsa.rsaKeyPair
let blindFactor : bigint

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

//get public RSA key
export async function getPublicKeyRSA(req: Request, res: Response) {

  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }  

  try {
       let data = {
        e: bc.bigintToHex(keyPair.publicKey.e),
        n: bc.bigintToHex(keyPair.publicKey.n),
      }; 
      console.log("Sending public key")
      res.status(200).send(data);
    } catch (err) {
      res.status(500).json({ message: "Server error" });
      console.log("Internal error ocurred: ", err)
    }
  }

//encryp text message with public public key
export async function encryptMessage (req: Request, res: Response) {

  const message:string = req.body.message;
  const m:bigint=bc.textToBigint(message)

  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }

  try {
       let data = {
        encrypted_message: String(keyPair.publicKey.encrypt(m)), 
      }; 
      console.log("Sending encrypted message: ", keyPair.publicKey.encrypt(m))
      res.status(200).send(data);
    } catch (err) {
      res.status(500).json({ message: "Server error" }); 
      console.log("Internal error ocurred: ", err)
    }
  }

//encryp message encrypted or message in BigInt format
export async function encryptBlind (req: Request, res: Response) {

  const m:bigint=BigInt(req.body.message)

  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }

  try {
       let data = {
        encrypted_message: String(keyPair.publicKey.encrypt(m)), 
      }; 
      console.log("Sending encrypted message: ", keyPair.publicKey.encrypt(m))
      res.status(200).send(data);
    } catch (err) {
      res.status(500).json({ message: "Server error" }); 
      console.log("Internal error ocurred: ", err)
    }
  }

//decryp message with private key
export async function decrypt (req: Request, res: Response) {

  const encrypted_message : bigint =  BigInt(req.body.message); 

  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }

  try{
    let data = {
    decrypted_message: bc.bigintToText(keyPair.privateKey.decrypt(encrypted_message)),
  }; 
  console.log("Sending decrypted message: ", keyPair.privateKey.decrypt(encrypted_message))
  res.status(200).send(data);
} catch (err) {
  res.status(500).json({ message: "Server error" });
  console.log("Internal error ocurred: ", err)
    }
}

//sign message with private key
export async function signMessage (req: Request, res: Response) {
  
  const message:string = req.body.message;
  const m:bigint=bc.textToBigint(message)
    
  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }

  try {
    let data = {
    signed_message: String(keyPair.privateKey.sign(m)), 
    }; 
    console.log("Sending signed bigint message: ", keyPair.privateKey.sign(m))
    res.status(200).send(data);
  }catch (err) {
    res.status(500).json({ message: "Server error" }); 
      console.log("Internal error ocurred: ", err)
  }
  }

  //sign message with private key
export async function signBlind (req: Request, res: Response) {
  
  
  const m:bigint=BigInt(req.body.message);
    
  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }

  try {
    let data = {
    signed_message: String(keyPair.privateKey.sign(m)), 
    }; 
    console.log("Sending signed bigint message: ", keyPair.privateKey.sign(m))
    res.status(200).send(data);
  }catch (err) {
    res.status(500).json({ message: "Server error" }); 
      console.log("Internal error ocurred: ", err)
  }
  }

//get blind identity
export async function getBlind (req: Request, res: Response) {
  
  //blindFactor =  BigInt(Math.random() * 100
  blindFactor = 123456789n
  console.log("blind factor", blindFactor)
 
  const blindedMessage = keyPair.publicKey.encrypt(blindFactor)
  console.log("blinded message", blindedMessage)
  

  try {
    let data = {
    blinded_message: String( blindedMessage), 
    }; 
    res.status(200).send(data);
  }catch (err) {
    res.status(500).json({ message: "Server error" }); 
      console.log("Internal error ocurred: ", err)
  }
  }

//unlind
export async function unblind (req: Request, res: Response) {
  
 
  const blindSigned:bigint = BigInt(req.body.message);

  //const hashed_message = sha256(message)


  const unblindedMessage : bigint = modInv( (blindSigned / blindFactor) , keyPair.privateKey.n)
  
  console.log("Unblinded message", unblindedMessage)
  
  try {
    let data = {
    unblinded_message: String( unblindedMessage), 
    }; 
    res.status(200).send(data);
  }catch (err) {
    res.status(500).json({ message: "Server error" }); 
      console.log("Internal error ocurred: ", err)
  }
  }
    
export async function verifyMessage (req: Request, res: Response) {
    
const signed_message: bigint =  BigInt(req.body.signed); 
const original_message: string = req.body.message

console.log("signed message: ", signed_message )
console.log("original message: ", original_message ) 
    
if(keyPair==null){
  res.status(500).json({ message: "Please generate a rsa key pair before!" });
  return;
}

try {
  const unsigned =  bc.bigintToText(keyPair.publicKey.verify(signed_message));
  console.log("unsigned bigint message : ", keyPair.publicKey.verify(signed_message))
  console.log("unsigned text message : ", unsigned)

  if(original_message.localeCompare(unsigned) == 0){
    res.status(200).send("The sign has been verified");
  }else  res.status(200).send("Not valid sign");

  } catch (err) {
    res.status(500).json({ message: "Server error" });
    console.log("Internal error ocurred: ", err)
  }
  }
  
export async function verifyBlind (req: Request, res: Response) {
    
  const signed_message: bigint =  BigInt(req.body.signed); 
  const original_message: bigint = BigInt(req.body.message)
  
  console.log("signed message: ", signed_message )
  console.log("original message: ", original_message ) 
      
  if(keyPair==null){
    res.status(500).json({ message: "Please generate a rsa key pair before!" });
    return;
  }
  
  try {
    const unsigned =  keyPair.publicKey.verify(signed_message);
    console.log("unsigned bigint message : ", keyPair.publicKey.verify(signed_message))
    
    if(original_message == unsigned){
      res.status(200).send("The sign has been verified");
    }else  res.status(200).send("Not valid sign");
  
    } catch (err) {
      res.status(500).json({ message: "Server error" });
      console.log("Internal error ocurred: ", err)
    }
  }  

  
