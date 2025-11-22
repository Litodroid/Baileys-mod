import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, createECDH, createSign, createVerify } from 'crypto';
/* @ts-ignore */
import * as libsignal from 'libsignal';
import { KEY_BUNDLE_TYPE } from '../Defaults/index.js';

// insure browser & node compatibility
const { subtle } = globalThis.crypto;

/** prefix version byte to the pub keys, required for some curve crypto functions */
export const generateSignalPubKey = (pubKey) => pubKey.length === 33 ? pubKey : Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);

export const Curve = {
    generateKeyPair: () => {
        try {
            // Intentar usar la API de libsignal si está disponible
            if (libsignal.KeyPair && typeof libsignal.KeyPair.generate === 'function') {
                const keyPair = libsignal.KeyPair.generate();
                return {
                    private: Buffer.from(keyPair.private),
                    // remove version byte
                    public: Buffer.from(keyPair.public.slice(1))
                };
            }
        } catch (e) {
            console.log('Error using libsignal.KeyPair.generate, falling back to native crypto');
        }
        
        // Usar implementación nativa de Node.js como fallback
        const ecdh = createECDH('prime256v1');
        ecdh.generateKeys();
        
        return {
            private: ecdh.getPrivateKey(),
            public: ecdh.getPublicKey().slice(1) // remove version byte
        };
    },
    sharedKey: (privateKey, publicKey) => {
        try {
            // Intentar usar la API de libsignal si está disponible
            if (libsignal.PrivateKey && typeof libsignal.PrivateKey.agree === 'function') {
                const shared = libsignal.PrivateKey.agree(privateKey, generateSignalPubKey(publicKey));
                return Buffer.from(shared);
            }
        } catch (e) {
            console.log('Error using libsignal.PrivateKey.agree, falling back to native crypto');
        }
        
        // Usar implementación nativa de Node.js como fallback
        const ecdh = createECDH('prime256v1');
        ecdh.setPrivateKey(privateKey);
        const shared = ecdh.computeSecret(generateSignalPubKey(publicKey));
        return Buffer.from(shared);
    },
    sign: (privateKey, buf) => {
        try {
            // Intentar usar la API de libsignal si está disponible
            if (libsignal.PrivateKey && typeof libsignal.PrivateKey.sign === 'function') {
                return libsignal.PrivateKey.sign(privateKey, buf);
            }
        } catch (e) {
            console.log('Error using libsignal.PrivateKey.sign, falling back to native crypto');
        }
        
        // Usar implementación nativa de Node.js como fallback
        try {
            // Crear un objeto ECDH para manejar la clave privada
            const ecdh = createECDH('prime256v1');
            ecdh.setPrivateKey(privateKey);
            
            // Crear un objeto de firma
            const sign = createSign('SHA256');
            sign.update(buf);
            
            // Firmar usando la clave privada directamente (sin opciones de formato)
            return sign.sign(ecdh.getPrivateKey());
        } catch (error) {
            console.error('Error in native crypto sign:', error);
            throw error;
        }
    },
    verify: (pubKey, message, signature) => {
        try {
            // Intentar usar la API de libsignal si está disponible
            if (libsignal.PublicKey && typeof libsignal.PublicKey.verify === 'function') {
                libsignal.PublicKey.verify(generateSignalPubKey(pubKey), message, signature);
                return true;
            }
        } catch (e) {
            console.log('Error using libsignal.PublicKey.verify, falling back to native crypto');
        }
        
        // Usar implementación nativa de Node.js como fallback
        try {
            // Asegurarse de que la clave pública tenga el formato correcto
            const publicKey = generateSignalPubKey(pubKey);
            
            // Crear un objeto de verificación
            const verify = createVerify('SHA256');
            verify.update(message);
            
            // Verificar usando la clave pública directamente (sin opciones de formato)
            return verify.verify(publicKey, signature);
        } catch (error) {
            console.error('Error in native crypto verify:', error);
            return false;
        }
    }
};

export const signedKeyPair = (identityKeyPair, keyId) => {
    const preKey = Curve.generateKeyPair();
    const pubKey = generateSignalPubKey(preKey.public);
    const signature = Curve.sign(identityKeyPair.private, pubKey);
    return { keyPair: preKey, signature, keyId };
};

const GCM_TAG_LENGTH = 128 >> 3;

/**
 * encrypt AES 256 GCM;
 * where the tag tag is suffixed to the ciphertext
 * */
export function aesEncryptGCM(plaintext, key, iv, additionalData) {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(additionalData);
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

/**
 * decrypt AES 256 GCM;
 * where the auth tag is suffixed to the ciphertext
 * */
export function aesDecryptGCM(ciphertext, key, iv, additionalData) {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    // decrypt additional adata
    const enc = ciphertext.slice(0, ciphertext.length - GCM_TAG_LENGTH);
    const tag = ciphertext.slice(ciphertext.length - GCM_TAG_LENGTH);
    // set additional data
    decipher.setAAD(additionalData);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]);
}

export function aesEncryptCTR(plaintext, key, iv) {
    const cipher = createCipheriv('aes-256-ctr', key, iv);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

export function aesDecryptCTR(ciphertext, key, iv) {
    const decipher = createDecipheriv('aes-256-ctr', key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** decrypt AES 256 CBC; where the IV is prefixed to the buffer */
export function aesDecrypt(buffer, key) {
    return aesDecryptWithIV(buffer.slice(16, buffer.length), key, buffer.slice(0, 16));
}

/** decrypt AES 256 CBC */
export function aesDecryptWithIV(buffer, key, IV) {
    const aes = createDecipheriv('aes-256-cbc', key, IV);
    return Buffer.concat([aes.update(buffer), aes.final()]);
}

// encrypt AES 256 CBC; where a random IV is prefixed to the buffer
export function aesEncrypt(buffer, key) {
    const IV = randomBytes(16);
    const aes = createCipheriv('aes-256-cbc', key, IV);
    return Buffer.concat([IV, aes.update(buffer), aes.final()]); // prefix IV to the buffer
}

// encrypt AES 256 CBC with a given IV
export function aesEncrypWithIV(buffer, key, IV) {
    const aes = createCipheriv('aes-256-cbc', key, IV);
    return Buffer.concat([aes.update(buffer), aes.final()]); // prefix IV to the buffer
}

// sign HMAC using SHA 256
export function hmacSign(buffer, key, variant = 'sha256') {
    return createHmac(variant, key).update(buffer).digest();
}

export function sha256(buffer) {
    return createHash('sha256').update(buffer).digest();
}

export function md5(buffer) {
    return createHash('md5').update(buffer).digest();
}

// HKDF key expansion
export async function hkdf(buffer, expandedLength, info) {
    // Ensure we have a Uint8Array for the key material
    const inputKeyMaterial = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    // Set default values if not provided
    const salt = info.salt ? new Uint8Array(info.salt) : new Uint8Array(0);
    const infoBytes = info.info ? new TextEncoder().encode(info.info) : new Uint8Array(0);
    // Import the input key material
    const importedKey = await subtle.importKey('raw', inputKeyMaterial, { name: 'HKDF' }, false, ['deriveBits']);
    // Derive bits using HKDF
    const derivedBits = await subtle.deriveBits({
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: infoBytes
    }, importedKey, expandedLength * 8 // Convert bytes to bits
    );
    return Buffer.from(derivedBits);
}

export async function derivePairingCodeKey(pairingCode, salt) {
    // Convert inputs to formats Web Crypto API can work with
    const encoder = new TextEncoder();
    const pairingCodeBuffer = encoder.encode(pairingCode);
    const saltBuffer = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
    // Import the pairing code as key material
    const keyMaterial = await subtle.importKey('raw', pairingCodeBuffer, { name: 'PBKDF2' }, false, ['deriveBits']);
    // Derive bits using PBKDF2 with the same parameters
    // 2 << 16 = 131,072 iterations
    const derivedBits = await subtle.deriveBits({
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 2 << 16,
        hash: 'SHA-256'
    }, keyMaterial, 32 * 8 // 32 bytes * 8 = 256 bits
    );
    return Buffer.from(derivedBits);
}
//# sourceMappingURL=crypto.js.map
