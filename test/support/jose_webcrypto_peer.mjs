// Independent RFC 7515/7516 compact peer using only Node WebCrypto.
import { webcrypto, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
const { subtle } = webcrypto;
const b64 = b => Buffer.from(b).toString('base64url');
const dec = s => Buffer.from(s, 'base64url');
const utf8 = s => Buffer.from(s, 'utf8');
const hash = a => a.endsWith('384') ? 'SHA-384' : a.endsWith('512') ? 'SHA-512' : 'SHA-256';
const jwsSpec = a => a === 'EdDSA' ? {name:'Ed25519'} : a.startsWith('ES') ? {name:'ECDSA',namedCurve:a==='ES256'?'P-256':'P-384',hash:hash(a)} : a==='HS256' ? {name:'HMAC',hash:'SHA-256',length:256} : {name:a==='RS256'?'RSASSA-PKCS1-v1_5':'RSA-PSS',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:hash(a),saltLength:Number(a.slice(2))/8};
const oaepSpec = a => ({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:a==='RSA-OAEP'?'SHA-1':'SHA-256'});
async function importKey(jwk,spec,usage) {
  const clean = {...jwk}; delete clean.alg; delete clean.use; delete clean.key_ops;
  if (spec.name==='HMAC' && dec(clean.k).length*8 !== spec.length) throw Error('key length');
  return subtle.importKey('jwk',clean,spec,true,[usage]);
}
async function sign(alg,key,payload) {
  const protectedPart=b64(utf8(JSON.stringify({alg})));
  const base=protectedPart+'.'+b64(payload);
  const k=await importKey(key,jwsSpec(alg),'sign');
  return base+'.'+b64(await subtle.sign(jwsSpec(alg),k,utf8(base)));
}
async function verify(alg,key,compact) {
  const [p,b,s]=compact.split('.');
  if (JSON.parse(dec(p)).alg !== alg) return false;
  return subtle.verify(jwsSpec(alg),await importKey(key,jwsSpec(alg),'verify'),dec(s),utf8(p+'.'+b));
}
async function encrypt(alg,enc,key,plaintext) {
  const cek = alg==='dir' ? dec(key.k) : randomBytes(enc==='A128GCM'?16:32);
  const iv=randomBytes(12); const h={alg,enc}; let ek=Buffer.alloc(0);
  if (alg.startsWith('RSA')) ek=Buffer.from(await subtle.encrypt(oaepSpec(alg),await importKey(key,oaepSpec(alg),'encrypt'),cek));
  if (alg.endsWith('GCMKW')) {
    const wiv=randomBytes(12);
    const kek=await importKey(key,{name:'AES-GCM'},'encrypt');
    const sealed=Buffer.from(await subtle.encrypt({name:'AES-GCM',iv:wiv,tagLength:128},kek,cek));
    ek=sealed.subarray(0,-16);h.iv=b64(wiv);h.tag=b64(sealed.subarray(-16));
  }
  const p=b64(utf8(JSON.stringify(h)));
  const k=await subtle.importKey('raw',cek,{name:'AES-GCM'},false,['encrypt']);
  const sealed=Buffer.from(await subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8(p),tagLength:128},k,plaintext));
  return [p,b64(ek),b64(iv),b64(sealed.subarray(0,-16)),b64(sealed.subarray(-16))].join('.');
}
async function decrypt(alg,enc,key,compact) {
  const [p,ek,iv,ct,tag]=compact.split('.');const h=JSON.parse(dec(p));
  if(h.alg!==alg||h.enc!==enc)throw Error('selection');
  let cek;
  if(alg==='dir')cek=dec(key.k);
  else if(alg.startsWith('RSA'))cek=await subtle.decrypt(oaepSpec(alg),await importKey(key,oaepSpec(alg),'decrypt'),dec(ek));
  else cek=await subtle.decrypt({name:'AES-GCM',iv:dec(h.iv),tagLength:128},await importKey(key,{name:'AES-GCM'},'decrypt'),Buffer.concat([dec(ek),dec(h.tag)]));
  const k=await subtle.importKey('raw',cek,{name:'AES-GCM'},false,['decrypt']);
  return b64(await subtle.decrypt({name:'AES-GCM',iv:dec(iv),additionalData:utf8(p),tagLength:128},k,Buffer.concat([dec(ct),dec(tag)])));
}
async function generated(spec) {
  const key=await subtle.generateKey(spec,true,['sign','verify']);
  return key.privateKey ? {private:await subtle.exportKey('jwk',key.privateKey),public:await subtle.exportKey('jwk',key.publicKey)} : {private:await subtle.exportKey('jwk',key),public:await subtle.exportKey('jwk',key)};
}
async function respond(r) {
  if(r.operation==='make') {
    const alg=r.algorithm,enc=r.encryption;
    let key;
    if(alg.startsWith('RSA')) {
      const pair=await subtle.generateKey(oaepSpec(alg),true,['encrypt','decrypt']);
      key={private:await subtle.exportKey('jwk',pair.privateKey),public:await subtle.exportKey('jwk',pair.publicKey)};
    } else {
      const k=randomBytes(alg==='A128GCMKW'||(alg==='dir'&&enc==='A128GCM')?16:32);
      key={private:{kty:'oct',k:b64(k)},public:{kty:'oct',k:b64(k)}};
    }
    const sk=await generated(jwsSpec(r.signature_algorithm));
    // Bind exported material to this peer's selected RFC 7518 token.
    sk.private.alg=r.signature_algorithm; sk.public.alg=r.signature_algorithm;
    const plaintext=randomBytes(r.length);
    const payload=randomBytes(Math.max(1,r.length));
    return {key:key.private,signing_key:sk.private,verification_key:sk.public,plaintext:b64(plaintext),payload:b64(payload),jwe:await encrypt(alg,enc,key.public,plaintext),jws:await sign(r.signature_algorithm,sk.private,payload)};
  }
  if(r.operation==='verify')return {valid:await verify(r.algorithm,r.key,r.compact)};
  if(r.operation==='encrypt')return {jwe:await encrypt(r.algorithm,r.encryption,r.key,dec(r.plaintext))};
  if(r.operation==='decrypt')return {plaintext:await decrypt(r.algorithm,r.encryption,r.key,r.compact)};
  throw Error('operation');
}
const rl=createInterface({input:process.stdin,crlfDelay:Infinity});
for await (const line of rl) {
  try { console.log(JSON.stringify(await respond(JSON.parse(line)))); }
  catch { console.log(JSON.stringify({error:'rejected'})); process.exitCode=1; }
}
