// Independent panva/jose producer and reciprocal consumer. Test keys only.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { randomBytes, createHash, diffieHellman, createPrivateKey, createPublicKey } from 'node:crypto';
const jose = await import(pathToFileURL(process.env.REQUESTSEAL_NPM_JOSE));
const [mode, input, output] = process.argv.slice(2);
const b64 = b => Buffer.from(b).toString('base64url');
const configurations = ['P-256', 'X25519'].flatMap(curve => ['ECDH-ES', 'ECDH-ES+A256KW'].map(alg => ({alg, curve})))
  .concat(['A128KW', 'A256KW', 'A128GCMKW', 'A256GCMKW', 'dir'].map(alg => ({alg})));
async function make() {
  const rows = [];
  for (const {alg, curve} of configurations) for (const enc of ['A128GCM', 'A256GCM']) {
    let privateJwk, publicKey, ephemeralPrivate;
    if (curve) {
      const pair = await jose.generateKeyPair(alg, {crv: curve, extractable: true});
      privateJwk = await jose.exportJWK(pair.privateKey);
      publicKey = pair.publicKey;
      const ephemeral = await jose.generateKeyPair(alg, {crv: curve, extractable: true});
      ephemeralPrivate = await jose.exportJWK(ephemeral.privateKey);
    } else {
      const width = alg.startsWith('A128') ? 16 : alg === 'dir' && enc === 'A128GCM' ? 16 : 32;
      privateJwk = {kty: 'oct', k: b64(randomBytes(width))};
      publicKey = await jose.importJWK(privateJwk, alg);
    }
    const plaintext = randomBytes(53);
    const producer = new jose.CompactEncrypt(plaintext).setProtectedHeader({alg, enc});
    let cek;
    if (curve) {
      const epk = await jose.importJWK(ephemeralPrivate, alg);
      producer.setKeyManagementParameters({epk, apu: new TextEncoder().encode('Alice'), apv: new TextEncoder().encode('Bob')});
    }
    if (alg !== 'ECDH-ES' && alg !== 'dir') {
      cek = randomBytes(enc === 'A128GCM' ? 16 : 32);
      producer.setContentEncryptionKey(cek);
    }
    const token = await producer.encrypt(publicKey);
    const decrypted = await jose.compactDecrypt(token, await jose.importJWK(privateJwk, alg));
    if (!Buffer.from(decrypted.plaintext).equals(plaintext)) throw new Error('npm producer verification');
    const row = {provider: 'npm-jose-6.2.17', alg, enc, key: privateJwk, token, plaintext: b64(plaintext)};
    if (curve) {
      const publicJwk = {...privateJwk}; delete publicJwk.d;
      const z = diffieHellman({privateKey: createPrivateKey({key: ephemeralPrivate, format: 'jwk'}), publicKey: createPublicKey({key: publicJwk, format: 'jwk'})});
      const field = data => {data = Buffer.from(data); const len = Buffer.alloc(4); len.writeUInt32BE(data.length); return Buffer.concat([len, data]);};
      const id = alg === 'ECDH-ES' ? enc : alg;
      const bits = alg === 'ECDH-ES' && enc === 'A128GCM' ? 128 : 256;
      const counter = Buffer.from([0,0,0,1]); const length = Buffer.alloc(4); length.writeUInt32BE(bits);
      const derived = createHash('sha256').update(Buffer.concat([counter,z,field(id),field('Alice'),field('Bob'),length])).digest().subarray(0,bits/8);
      row.agreement = {ephemeral_private: ephemeralPrivate.d, cek: b64(cek ?? derived), encrypted_key: token.split('.')[1], epk: JSON.parse(Buffer.from(token.split('.')[0], 'base64url')).epk, apu: b64('Alice'), apv: b64('Bob')};
    }
    rows.push(row);
  }
  writeFileSync(output, JSON.stringify(rows));
}
if (mode === 'make') await make();
else if (mode === 'verify') {
  const rows = JSON.parse(readFileSync(input));
  for (const row of rows) {
    const {plaintext} = await jose.compactDecrypt(row.token, await jose.importJWK(row.key, row.alg));
    if (b64(plaintext) !== row.plaintext) throw new Error(`npm reciprocal ${row.alg}`);
  }
  process.stdout.write(`PASS npm jose 6.2.17 decrypted ${rows.length} RequestSeal envelopes\n`);
} else throw new Error('mode');
