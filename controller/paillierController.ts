import { Request,Response } from 'express';
import * as paillier from '../models/paillier'
import * as bc from "bigint-conversion";


let paillierKeys: paillier.paillierKeyPair

export async function generatePaillierKeys(req: Request, res : Response) {
    console.log("Generating the keys, wait a moment please")

    try{
        paillierKeys = await paillier.generatePaillierKeys()
        if(paillierKeys){
            res.status(200).send("Paillier keys generated succesfully!")
        }

    }catch(err){
        res.status(501).send("Internal error")
    }  

}

export async function encrypt(req : Request, res : Response){
    const message: string = req.body.message
    const m : bigint = bc.textToBigint(message)

    try{
        let encrypted:BigInt = paillierKeys.publicKey.encrypt(m)
        let data = {
            encrypted_message : String(encrypted)
        }
        res.status(200).send(data)
    }catch(err){
        res.status(500).json({ message: "Server error" }); 
        console.log(err)
    }

}

export async function decrypt(req : Request, res : Response){
    const encrypted_message: bigint =  BigInt(req.body.message);

    try{
        let data = {
            decrypted_message: bc.bigintToText(paillierKeys.privateKey.decrypt(encrypted_message))
        }
        res.status(200).send(data)
    }catch(err){
        res.status(500).json({ message: "Server error" }); 
        console.log(err)
    }

}
