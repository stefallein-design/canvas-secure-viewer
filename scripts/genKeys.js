import { generateKeyPair, exportJWK } from "jose";

function pickPublicFields(jwk) {
  // haal private velden weg
  const { d, p, q, dp, dq, qi, oth, ...pub } = jwk;
  return pub;
}

function randomKid() {
  return "kid-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

const kid = randomKid();

// RS256 is de meest gangbare keuze voor LTI 1.3
const { publicKey, privateKey } = await generateKeyPair("RS256", { modulusLength: 2048 });

const privateJwk = await exportJWK(privateKey);
privateJwk.kid = kid;
privateJwk.use = "sig";
privateJwk.alg = "RS256";

const publicJwk = pickPublicFields(await exportJWK(publicKey));
publicJwk.kid = kid;
publicJwk.use = "sig";
publicJwk.alg = "RS256";

console.log("=== COPY THIS INTO RENDER ENV: TOOL_PRIVATE_JWK ===");
console.log(JSON.stringify(privateJwk));
console.log("\n=== PUBLIC JWKS (for your reference) ===");
console.log(JSON.stringify({ keys: [publicJwk] }));
