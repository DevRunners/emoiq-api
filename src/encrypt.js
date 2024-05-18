
import { Buffer } from 'node:buffer';
import crypto from 'crypto';

// Función asincrónica para generar un par de claves RSA
async function generateRSAKeyPair() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-512",
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Exporta la clave pública y privada en formatos compatibles
  const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);
  const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', privateKey);

  // Convierte las claves exportadas a base64
  const expPublicKeyBase64 = Buffer.from(exportedPublicKey).toString('base64');
  const expPrivateKeyBase64 = Buffer.from(exportedPrivateKey).toString('base64');

  return { expPublicKeyBase64, expPrivateKeyBase64 }; // Retorna las claves en formato base64
}

// Función asincrónica para establecer las variables de entorno con las claves generadas
export async function setEnvVariables() {
  const { expPublicKeyBase64, expPrivateKeyBase64 } = await generateRSAKeyPair();
  process.env.PUBLIC_KEY = expPublicKeyBase64; // Almacena la clave pública en una variable de entorno
  process.env.PRIVATE_KEY = expPrivateKeyBase64; // Almacena la clave privada en una variable de entorno
}

// Función asincrónica para importar la clave privada RSA y configurarla para descifrar
async function importPrivateDecryptKey() {
  const privateKeyBase64String = Buffer.from(process.env.PRIVATE_KEY).toString('ascii'); // Obtiene la clave privada en formato base64
  const privateKeyBuffer = Buffer.from(privateKeyBase64String, 'base64'); // Convierte la clave privada a un búfer
  const privateCryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer,
    { name: 'RSA-OAEP', hash: "SHA-512" },
    false,
    ["decrypt"]
  ); // Importa la clave privada para descifrar
  return privateCryptoKey;
}

// Función asincrónica para descifrar una contraseña encriptada utilizando la clave privada RSA
export async function decryptedPassword(password) {
  const privateKey = await importPrivateDecryptKey(); // Importa la clave privada RSA
  const passwordBase64String = Buffer.from(password).toString('ascii'); // Convierte la contraseña encriptada a formato base64
  const passwordBuffer = Buffer.from(passwordBase64String, 'base64'); // Convierte la contraseña encriptada a un búfer
  const passwordBuff = await crypto.subtle.decrypt('RSA-OAEP', privateKey, passwordBuffer); // Descifra la contraseña
  const passwordDecrypted = Buffer.from(passwordBuff).toString('ascii'); // Convierte la contraseña descifrada a formato ASCII
  return passwordDecrypted; // Retorna la contraseña descifrada
}
