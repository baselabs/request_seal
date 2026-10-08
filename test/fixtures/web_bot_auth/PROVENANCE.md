# Web Bot Auth fixture provenance

**Status:** current · **Kind:** reference · **Updated:** 2026-10-08 · **Governed by:** draft-ietf-webbotauth-httpsig-protocol-00 · **Review when:** source bytes or signing inputs change

Retrieved and generated October 8, 2026.

- Draft: https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.txt
- Draft SHA-256: `3021fd94cdffdb2eb030dec68b1a5c968f2348502dd94c481e2085ec7ddd90a0`.
- `protocol-00.json`: Appendix E.1.1, E.1.2, E.2.1, E.2.2, E.2.3; RFC 8792 wraps removed, LF base lines, no final LF. IETF Code Components, Revised BSD license in NOTICE. Copyright 2026 IETF Trust and the document authors.
- E.1.1 and E.2.1 are generic cryptographic vectors. Their `sig2` label and `agent2` member contradict Section 5.2.1. Their 3,153,600,000-second lifetime exceeds the policy ceiling and Section 5.2's recommended 24 hours. These bytes are preserved as profile rejection vectors.
- Independent implementation: https://github.com/cloudflare/web-bot-auth at commit `6a8ece9bd2a64d83fc7bf3d7f9fd7886900a7355`.
- Package: `web-bot-auth@0.2.0`, https://registry.npmjs.org/web-bot-auth/-/web-bot-auth-0.2.0.tgz
- Integrity from `npm view web-bot-auth@0.2.0 dist.integrity`: `sha512-3DJ72ZhWK4a3yCHCClF6q32g03X37DJlpyASYeBroGTRj/qFkHNcPwkESc3FLigjW6NOWF6MR+Hat9AfOqqtAQ==`.
- `web_bot_auth_architecture_v2.json`: unchanged upstream `packages/web-bot-auth/test/test_data/web_bot_auth_architecture_v2.json`, SHA-256 `d0c8dbb7631dcc22639d12318af2b1ac0a339e4fa5aa4ef6df67ca45b0094576`.
- Upstream Apache-2.0 license retained verbatim in LICENSE, SHA-256 `c442cd87211d2bab6c01bce90efc4e8509db3dc712eebf377e44e47f4e1ffded`. Copyright belongs to the upstream contributors.
- `requests.json`: actual output from the pinned package on Node `24.21.0`; published RFC 9421 test keys. RSA JWK comes from the upstream vector. Inputs select matching agent labels and one-hour lifetimes. Nested omission is an independently signed rejection case.
- `directory.json`: the package's signing API accepts requests only. OpenSSL `pkeyutl -sign -rawin` signs the hand-derived Appendix B.1 response base. This is independent primitive evidence, separate from the published E.2.3 vector and real TLS adapter checks.

The generator also used these installed transitive packages; pin them when regenerating:

| Package | Version | npm integrity |
|---|---|---|
| `http-message-sig` | `0.3.0` | `sha512-ossX5ZDDCRD+YtMzryp3gCg+5wqLFes1RVChEFmEE9Bzbd49Ts2IIIvFnTst/mYWx0ivrxrTTPsIIKKJ07s7+w==` |
| `jsonwebkey-thumbprint` | `0.1.0` | `sha512-4m/gJEUQH8N2NfvZFjCL8/E+vlt0FlrmHoR4T93CEXQRkC64qwRi6oQri4/eqLVXqEqXYCss0+Q7pLx6vJBqzw==` |
| `structured-headers` | `2.0.3` | `sha512-4g5yxhlDMClRwCcfKfLeS7Z8yAVdOWGDADwm80Poh1iReU2KVKLGBlqwpHWJ2qovq0+ZIf1atAEO1eua2o9Rgg==` |

The package was installed once in a scratch directory outside the repository, with no project dependency added. Put the published RFC 9421 Ed25519 private PEM at `keys/ed25519_private.pem` and the unchanged upstream vector at `implementation.json`. Run the following with Node 24.21.0 after `npm install --save-exact web-bot-auth@0.2.0 http-message-sig@0.3.0 jsonwebkey-thumbprint@0.1.0 structured-headers@2.0.3 --ignore-scripts`:

```javascript
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import { sign } from 'web-bot-auth';
import { signerFromJWK } from 'web-bot-auth/crypto';
if (process.version !== 'v24.21.0') throw new Error('Node pin');
// Published RFC 9421 keys used by draft protocol-00 Appendix E.
const jwks = ['ed25519', 'rsa_pss'].map(name => {
 const jwk = name === 'rsa_pss' ? JSON.parse(readFileSync('implementation.json'))[0].key : createPrivateKey(readFileSync(`keys/${name}_private.pem`)).export({format:'jwk'});
 if (name === 'rsa_pss') jwk.alg = 'PS512';
 return jwk;
});
const vectors = [];
async function produce(name, fields, options = {}, key = 0) {
 const request = {kind:'request', method:'GET', targetUri:'https://example.com/resource?item=1', fields};
 const primitive = await signerFromJWK(jwks[key]);
 let base;
 const signer = {...primitive, sign(bytes) { base = Buffer.from(bytes).toString(); return primitive.sign(bytes); }};
 const signed = await sign(request, {signer, created:new Date(1735689600000), expires:new Date(1735693200000), nonce:Buffer.alloc(64,42).toString('base64'), label:'agent', ...options});
 const v = {name, method:request.method, target:request.targetUri, fields:[...fields.map(f=>[f.name,f.value]), ['Signature-Input',signed.signatureInput],['Signature',signed.signature]], base, algorithm:signer.algorithm};
 vectors.push(v);return v;
}
for (const type of ['directory','jwks_uri','cimd']) {
 const location = type === 'directory' ? 'https://signature-agent.test' : 'https://signature-agent.test/keys';
 await produce(type,[{name:'Signature-Agent',value:`agent="${location}";type=${type}`}]);
}
await produce('target-uri',[{name:'Signature-Agent',value:'agent="https://signature-agent.test"'}],{target:'@target-uri'});
await produce('rsa',[{name:'Signature-Agent',value:'agent="https://signature-agent.test"'}],{},1);
await produce('held-key',[]);
await produce('member-mismatch',[{name:'Signature-Agent',value:'agent2="https://signature-agent.test"'}],{signatureAgentKey:'agent2'});
const digest = 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:';
await produce('content',[{name:'Signature-Agent',value:'agent="https://signature-agent.test"'},{name:'Content-Digest',value:digest}],{additionalComponents:['content-digest']});
const agents = {name:'Signature-Agent',value:'agent="https://signature-agent.test", browser="https://browser.example"'};
const inner = await produce('inner',[agents],{additionalComponents:['@method','@path']});
await produce('nested',inner.fields.map(([name,value])=>({name,value})),{label:'browser',additionalComponents:['@method','@path',{name:'signature-agent',parameters:{key:'agent'}},{name:'signature-input',parameters:{key:'agent'}},{name:'signature',parameters:{key:'agent'}}]});
await produce('nested-incomplete',inner.fields.map(([name,value])=>({name,value})),{label:'browser',additionalComponents:[{name:'signature-input',parameters:{key:'agent'}},{name:'signature',parameters:{key:'agent'}}]});
writeFileSync('requests.json',JSON.stringify(vectors,null,2)+'\n');
console.log(`Generated ${vectors.length} independently signed requests`);
// The web-bot-auth API accepts requests only. For the directory response,
// derive the Appendix B.1 base by hand and sign it using OpenSSL.
const {spawnSync} = await import('node:child_process');
const publicKeys = [];
for (const jwk of jwks) {
 const signer = await signerFromJWK(jwk);
 const publicKey = jwk.kty === 'OKP' ? {kty:'OKP',crv:'Ed25519',x:jwk.x} : {kty:'RSA',n:jwk.n,e:jwk.e};
 publicKeys.push({...publicKey,kid:signer.keyid,use:'sig'});
}
const body = JSON.stringify({keys:publicKeys});
const {createHash} = await import('node:crypto');
const contentDigest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
const directorySigner = await signerFromJWK(jwks[0]);
const signatureInput = `directory=("@authority";req "content-digest");created=1735689600;expires=1735693200;keyid="${directorySigner.keyid}";tag="http-message-signatures-directory"`;
const base = `"@authority";req: signature-agent.test\n"content-digest": ${contentDigest}\n"@signature-params": ${signatureInput.slice('directory='.length)}`;
writeFileSync('directory-base',base);
const result = spawnSync('openssl',['pkeyutl','-sign','-rawin','-inkey','keys/ed25519_private.pem','-in','directory-base']);
if (result.status !== 0) throw new Error(result.stderr.toString());
writeFileSync('directory.json',JSON.stringify({body,base,fields:[['Content-Type','application/http-message-signatures-directory+json'],['Content-Digest',contentDigest],['Signature-Input',signatureInput],['Signature',`directory=:${result.stdout.toString('base64')}:`]]},null,2)+'\n');
console.log('Generated directory response with OpenSSL');
```

All keys here are public test material; never operational credentials. SHA256SUMS pins produced and vendored bytes. No fixture establishes acceptance by a deployed request verifier.
