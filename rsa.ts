import * as bcu from 'bigint-crypto-utils'



export class RsaPrivateKey {
  d: bigint
  n: bigint

  constructor (d: bigint, n: bigint) {
    this.d = d
    this.n = n
  }

  decrypt (c: bigint): bigint {
    return bcu.modPow(c, this.d, this.n)
  }

  sign (m: bigint): bigint {
    return bcu.modPow(m, this.d, this.n)
  }
}




export class RsaPublicKey {
  e: bigint
  n: bigint
  n2: bigint

  constructor (e: bigint, n: bigint) {
    this.e = e
    this.n = n
    this.n2 = this.n ** 2n // cache n^2
  }

  encrypt (m: bigint): bigint {
    return bcu.modPow(m, this.e, this.n)
  }

 
}
export interface rsaKeyPair {
    publicKey: RsaPublicKey
    privateKey: RsaPrivateKey
  }

export const generateKeys = async function (bitLength: number): Promise<rsaKeyPair> {
    const e = 65537n
    let p: bigint, q: bigint, n: bigint, phi: bigint
    do {
      p = await bcu.prime(bitLength / 2 + 1)
      q = await bcu.prime(bitLength / 2)
      n = p * q
      phi = (p - 1n) * (q - 1n)
    } while (bcu.bitLength(n) !== bitLength || (phi % e === 0n))
  
    const publicKey = new RsaPublicKey(e, n)
  
    const d = bcu.modInv(e, phi)
  
    const privateKey = new RsaPrivateKey(d, n)
  
    return {
      publicKey,
      privateKey
    }
  }

  export const testBcu = async function(){
      let p:bigint
      try{
        p = await bcu.prime(140)
        console.log(p)

      }catch(e){
          console.log()
      }

      

  }