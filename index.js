const crypto = require("crypto");

const Alice = crypto.createECDH("secp256k1");
Alice.generateKeys();

const bob = crypto.createECDH("secp256k1");
bob.generateKeys();

const AlicePublicBaseKey64 = Alice.getPublicKey().toString("base64");
const BobPublicBaseKey64 = bob.getPublicKey().toString("base64");

const AliceSharedKey = Alice.computeSecret(BobPublicBaseKey64, "base64", "hex");
const bobSharedKey = bob.computeSecret(AlicePublicBaseKey64, "base64", "hex");

/*
console.log(AliceSharedKey === bobSharedKey);
console.log("Alice Shared Key", AliceSharedKey);
console.log("Bob Shared Key", bobSharedKey);
*/

const Message = "This is a random message";

const IV = crypto.randomBytes(16);

const cipher = crypto.createCipheriv(
  "aes-256-gcm",
  Buffer.from(AliceSharedKey, "hex"),
  IV
);

let encrypted = cipher.update(Message, "utf8", "hex");
encrypted += cipher.final("hex");

const auth_tag = cipher.getAuthTag().toString("hex");

console.table({
  IV: IV.toString("hex"),
  encrypted: encrypted,
  auth_tag: auth_tag,
});

const payload = IV.toString("hex") + encrypted + auth_tag;

const payload64 = Buffer.from(payload, "hex").toString("base64");
console.log(payload64);

//Bob starts from here
const bob_payload = Buffer.from(payload64, "base64").toString("hex");

const bob_iv = bob_payload.substr(0, 32);
const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 - 32);
const bob_auth_tag = bob_payload.substr(bob_payload.length - 32, 32);

console.table({ bob_iv, bob_encrypted, bob_auth_tag });

try {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(bobSharedKey, "hex"),
    Buffer.from(bob_iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(bob_auth_tag, "hex"));

  let decrypted = decipher.update(bob_encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  console.log("Decrypted Message : ", decrypted);
} catch (error) {
  console.log(error.message);
}
