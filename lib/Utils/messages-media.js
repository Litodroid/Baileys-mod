import { Boom } from '@hapi/boom';
import axios, {} from 'axios';
import { exec } from 'child_process';
import * as Crypto from 'crypto';
import { once } from 'events';
import { createReadStream, createWriteStream, promises as fs, WriteStream } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Readable, Transform } from 'stream';
import { URL } from 'url';
import { proto } from '../../WAProto/index.js';
import { DEFAULT_ORIGIN, MEDIA_HKDF_KEY_MAPPING, MEDIA_PATH_MAP } from '../Defaults/index.js';
import { getBinaryNodeChild, getBinaryNodeChildBuffer, jidNormalizedUser } from '../WABinary/index.js';
import { aesDecryptGCM, aesEncryptGCM, hkdf } from './crypto.js';
import { generateMessageIDV2 } from './generics.js';

// Importaciones adicionales necesarias
import FormData from 'form-data';
import cheerio from 'cheerio';
// Importación corregida de jimp
import * as jimp from 'jimp';
import { pipeline } from 'stream/promises';

const getTmpFilesDirectory = () => tmpdir();
const getImageProcessingLibrary = async () => {
    const sharp = await (Promise.resolve().then(() => import('sharp')).catch(() => { }));
    if (sharp) {
        return { sharp };
    }
    throw new Boom('No image processing library available');
};

export const hkdfInfoKey = (type) => {
    const hkdfInfo = MEDIA_HKDF_KEY_MAPPING[type];
    return `WhatsApp ${hkdfInfo} Keys`;
};

export const getRawMediaUploadData = async (media, mediaType, logger) => {
    const { stream } = await getStream(media);
    logger?.debug('got stream for raw upload');
    const hasher = Crypto.createHash('sha256');
    const filePath = join(tmpdir(), mediaType + generateMessageIDV2());
    const fileWriteStream = createWriteStream(filePath);
    let fileLength = 0;
    try {
        for await (const data of stream) {
            fileLength += data.length;
            hasher.update(data);
            if (!fileWriteStream.write(data)) {
                await once(fileWriteStream, 'drain');
            }
        }
        fileWriteStream.end();
        await once(fileWriteStream, 'finish');
        stream.destroy();
        const fileSha256 = hasher.digest();
        logger?.debug('hashed data for raw upload');
        return {
            filePath: filePath,
            fileSha256,
            fileLength
        };
    }
    catch (error) {
        fileWriteStream.destroy();
        stream.destroy();
        try {
            await fs.unlink(filePath);
        }
        catch {
            //
        }
        throw error;
    }
};

/** generates all the keys required to encrypt/decrypt & sign a media message */
export async function getMediaKeys(buffer, mediaType) {
    if (!buffer) {
        throw new Boom('Cannot derive from empty media key');
    }
    if (typeof buffer === 'string') {
        buffer = Buffer.from(buffer.replace('data:;base64,', ''), 'base64');
    }
    // expand using HKDF to 112 bytes, also pass in the relevant app info
    const expandedMediaKey = await hkdf(buffer, 112, { info: hkdfInfoKey(mediaType) });
    return {
        iv: expandedMediaKey.slice(0, 16),
        cipherKey: expandedMediaKey.slice(16, 48),
        macKey: expandedMediaKey.slice(48, 80)
    };
}

/** Extracts video thumb using FFMPEG */
const extractVideoThumb = async (path, destPath, time, size) => new Promise((resolve, reject) => {
    const cmd = `ffmpeg -ss ${time} -i ${path} -y -vf scale=${size.width}:-1 -vframes 1 -f image2 ${destPath}`;
    exec(cmd, err => {
        if (err) {
            reject(err);
        }
        else {
            resolve();
        }
    });
});

export const extractImageThumb = async (bufferOrFilePath, width = 32) => {
    if (bufferOrFilePath instanceof Readable) {
        bufferOrFilePath = await toBuffer(bufferOrFilePath);
    }
    const lib = await getImageProcessingLibrary();
    if ('sharp' in lib && typeof lib.sharp?.default === 'function') {
        const img = lib.sharp.default(bufferOrFilePath);
        const dimensions = await img.metadata();
        const buffer = await img.resize(width).jpeg({ quality: 50 }).toBuffer();
        return {
            buffer,
            original: {
                width: dimensions.width,
                height: dimensions.height
            }
        };
    }
    else {
        throw new Boom('No image processing library available');
    }
};

export const encodeBase64EncodedStringForUpload = (b64) => encodeURIComponent(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, ''));

export const generateProfilePicture = async (mediaUpload) => {
    let buffer;
    if (Buffer.isBuffer(mediaUpload)) {
        buffer = mediaUpload;
    }
    else {
        const { stream } = await getStream(mediaUpload);
        buffer = await toBuffer(stream);
    }
    const lib = await getImageProcessingLibrary();
    let img;
    if ('sharp' in lib && typeof lib.sharp?.default === 'function') {
        const image = lib.sharp.default(buffer);
        img = await image
            .resize(720, 720, { 
                fit: 'inside', 
                withoutEnlargement: true 
            })
            .jpeg({ 
                quality: 90, 
                mozjpeg: true 
            })
            .toBuffer();
    }
    else {
        throw new Boom('No image processing library available');
    }
    return {
        img
    };
};

/** gets the SHA256 of the given media message */
export const mediaMessageSHA256B64 = (message) => {
    const media = Object.values(message)[0];
    return media?.fileSha256 && Buffer.from(media.fileSha256).toString('base64');
};

export async function getAudioDuration(buffer) {
    const musicMetadata = await import('music-metadata');
    let metadata;
    const options = {
        duration: true
    };
    if (Buffer.isBuffer(buffer)) {
        metadata = await musicMetadata.parseBuffer(buffer, undefined, options);
    }
    else if (typeof buffer === 'string') {
        metadata = await musicMetadata.parseFile(buffer, options);
    }
    else {
        metadata = await musicMetadata.parseStream(buffer, undefined, options);
    }
    return metadata.format.duration;
}

/**
  referenced from and modifying https://github.com/wppconnect-team/wa-js/blob/main/src/chat/functions/prepareAudioWaveform.ts
 */
export async function getAudioWaveform(buffer, logger) {
    try {
        // @ts-ignore
        const { default: decoder } = await import('audio-decode');
        let audioData;
        if (Buffer.isBuffer(buffer)) {
            audioData = buffer;
        }
        else if (typeof buffer === 'string') {
            const rStream = createReadStream(buffer);
            audioData = await toBuffer(rStream);
        }
        else {
            audioData = await toBuffer(buffer);
        }
        const audioBuffer = await decoder(audioData);
        const rawData = audioBuffer.getChannelData(0); // We only need to work with one channel of data
        const samples = 64; // Number of samples we want to have in our final data set
        const blockSize = Math.floor(rawData.length / samples); // the number of samples in each subdivision
        const filteredData = [];
        for (let i = 0; i < samples; i++) {
            const blockStart = blockSize * i; // the location of the first sample in the block
            let sum = 0;
            for (let j = 0; j < blockSize; j++) {
                sum = sum + Math.abs(rawData[blockStart + j]); // find the sum of all the samples in the block
            }
            filteredData.push(sum / blockSize); // divide the sum by the block size to get the average
        }
        // This guarantees that the largest data point will be set to 1, and the rest of the data will scale proportionally.
        const multiplier = Math.pow(Math.max(...filteredData), -1);
        const normalizedData = filteredData.map(n => n * multiplier);
        // Generate waveform like WhatsApp
        const waveform = new Uint8Array(normalizedData.map(n => Math.floor(100 * n)));
        return waveform;
    }
    catch (e) {
        logger?.debug('Failed to generate waveform: ' + e);
    }
}

export const toReadable = (buffer) => {
    const readable = new Readable({ read: () => { } });
    readable.push(buffer);
    readable.push(null);
    return readable;
};

// MODIFICACIÓN PRINCIPAL: Reemplazar toBuffer con pipeline + escritura directa a disco
export const toBuffer = async (stream) => {
    // Crear un archivo temporal único
    const tempFilePath = join(tmpdir(), `media-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`);
    
    // Crear un stream de escritura
    const fileWriteStream = createWriteStream(tempFilePath);
    
    try {
        // Usar pipeline para transferir el stream directamente al disco
        await pipeline(stream, fileWriteStream);
        
        // Devolver la ruta del archivo en lugar del buffer
        return tempFilePath;
    } catch (error) {
        // En caso de error, intentar eliminar el archivo temporal
        try {
            await fs.unlink(tempFilePath);
        } catch (unlinkError) {
            console.error('Error al eliminar archivo temporal:', unlinkError);
        }
        throw error;
    }
};

export const getStream = async (item, opts) => {
    if (Buffer.isBuffer(item)) {
        return { stream: toReadable(item), type: 'buffer' };
    }
    if ('stream' in item) {
        return { stream: item.stream, type: 'readable' };
    }
    const urlStr = item.url.toString();
    if (urlStr.startsWith('data:')) {
        const buffer = Buffer.from(urlStr.split(',')[1], 'base64');
        return { stream: toReadable(buffer), type: 'buffer' };
    }
    if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
        return { stream: await getHttpStream(item.url, opts), type: 'remote' };
    }
    return { stream: createReadStream(item.url), type: 'file' };
};

/** generates a thumbnail for a given media, if required */
export async function generateThumbnail(file, mediaType, options) {
    let thumbnail;
    let originalImageDimensions;
    if (mediaType === 'image') {
        const { buffer, original } = await extractImageThumb(file);
        thumbnail = buffer.toString('base64');
        if (original.width && original.height) {
            originalImageDimensions = {
                width: original.width,
                height: original.height
            };
        }
    }
    else if (mediaType === 'video') {
        const imgFilename = join(getTmpFilesDirectory(), generateMessageIDV2() + '.jpg');
        try {
            await extractVideoThumb(file, imgFilename, '00:00:00', { width: 32, height: 32 });
            const buff = await fs.readFile(imgFilename);
            thumbnail = buff.toString('base64');
            await fs.unlink(imgFilename);
        }
        catch (err) {
            options.logger?.debug('could not generate video thumb: ' + err);
        }
    }
    return {
        thumbnail,
        originalImageDimensions
    };
}

export const getHttpStream = async (url, options = {}) => {
    const fetched = await axios.get(url.toString(), { ...options, responseType: 'stream' });
    return fetched.data;
};

export const encryptedStream = async (media, mediaType, { logger, saveOriginalFileIfRequired, opts } = {}) => {
    const { stream, type } = await getStream(media, opts);
    logger?.debug('fetched media stream');
    const mediaKey = Crypto.randomBytes(32);
    const { cipherKey, iv, macKey } = await getMediaKeys(mediaKey, mediaType);
    const encFilePath = join(getTmpFilesDirectory(), mediaType + generateMessageIDV2() + '-enc');
    const encFileWriteStream = createWriteStream(encFilePath);
    let originalFileStream;
    let originalFilePath;
    if (saveOriginalFileIfRequired) {
        originalFilePath = join(getTmpFilesDirectory(), mediaType + generateMessageIDV2() + '-original');
        originalFileStream = createWriteStream(originalFilePath);
    }
    let fileLength = 0;
    const aes = Crypto.createCipheriv('aes-256-cbc', cipherKey, iv);
    const hmac = Crypto.createHmac('sha256', macKey).update(iv);
    const sha256Plain = Crypto.createHash('sha256');
    const sha256Enc = Crypto.createHash('sha256');
    const onChunk = (buff) => {
        sha256Enc.update(buff);
        hmac.update(buff);
        encFileWriteStream.write(buff);
    };
    try {
        for await (const data of stream) {
            fileLength += data.length;
            if (type === 'remote' && opts?.maxContentLength && fileLength + data.length > opts.maxContentLength) {
                throw new Boom(`content length exceeded when encrypting "${type}"`, {
                    data: { media, type }
                });
            }
            if (originalFileStream) {
                if (!originalFileStream.write(data)) {
                    await once(originalFileStream, 'drain');
                }
            }
            sha256Plain.update(data);
            onChunk(aes.update(data));
        }
        onChunk(aes.final());
        const mac = hmac.digest().slice(0, 10);
        sha256Enc.update(mac);
        const fileSha256 = sha256Plain.digest();
        const fileEncSha256 = sha256Enc.digest();
        encFileWriteStream.write(mac);
        encFileWriteStream.end();
        originalFileStream?.end?.();
        stream.destroy();
        logger?.debug('encrypted data successfully');
        return {
            mediaKey,
            originalFilePath,
            encFilePath,
            mac,
            fileEncSha256,
            fileSha256,
            fileLength
        };
    }
    catch (error) {
        // destroy all streams with error
        encFileWriteStream.destroy();
        originalFileStream?.destroy?.();
        aes.destroy();
        hmac.destroy();
        sha256Plain.destroy();
        sha256Enc.destroy();
        stream.destroy();
        try {
            await fs.unlink(encFilePath);
            if (originalFilePath) {
                await fs.unlink(originalFilePath);
            }
        }
        catch (err) {
            logger?.error({ err }, 'failed deleting tmp files');
        }
        throw error;
    }
};

const DEF_HOST = 'mmg.whatsapp.net';
const AES_CHUNK_SIZE = 16;
const toSmallestChunkSize = (num) => {
    return Math.floor(num / AES_CHUNK_SIZE) * AES_CHUNK_SIZE;
};

export const getUrlFromDirectPath = (directPath) => `https://${DEF_HOST}${directPath}`;

export const downloadContentFromMessage = async ({ mediaKey, directPath, url }, type, opts = {}) => {
    const isValidMediaUrl = url?.startsWith('https://mmg.whatsapp.net/');
    const downloadUrl = isValidMediaUrl ? url : getUrlFromDirectPath(directPath);
    if (!downloadUrl) {
        throw new Boom('No valid media URL or directPath present in message', { statusCode: 400 });
    }
    const keys = await getMediaKeys(mediaKey, type);
    return downloadEncryptedContent(downloadUrl, keys, opts);
};

/**
 * Decrypts and downloads an AES256-CBC encrypted file given the keys.
 * Assumes the SHA256 of the plaintext is appended to the end of the ciphertext
 * */
export const downloadEncryptedContent = async (downloadUrl, { cipherKey, iv }, { startByte, endByte, options } = {}) => {
    let bytesFetched = 0;
    let startChunk = 0;
    let firstBlockIsIV = false;
    // if a start byte is specified -- then we need to fetch the previous chunk as that will form the IV
    if (startByte) {
        const chunk = toSmallestChunkSize(startByte || 0);
        if (chunk) {
            startChunk = chunk - AES_CHUNK_SIZE;
            bytesFetched = chunk;
            firstBlockIsIV = true;
        }
    }
    const endChunk = endByte ? toSmallestChunkSize(endByte || 0) + AES_CHUNK_SIZE : undefined;
    const headers = {
        ...(options?.headers || {}),
        Origin: DEFAULT_ORIGIN
    };
    if (startChunk || endChunk) {
        headers.Range = `bytes=${startChunk}-`;
        if (endChunk) {
            headers.Range += endChunk;
        }
    }
    // download the message
    const fetched = await getHttpStream(downloadUrl, {
        ...(options || {}),
        headers,
        maxBodyLength: Infinity,
        maxContentLength: Infinity
    });
    let remainingBytes = Buffer.from([]);
    let aes;
    const pushBytes = (bytes, push) => {
        if (startByte || endByte) {
            const start = bytesFetched >= startByte ? undefined : Math.max(startByte - bytesFetched, 0);
            const end = bytesFetched + bytes.length < endByte ? undefined : Math.max(endByte - bytesFetched, 0);
            push(bytes.slice(start, end));
            bytesFetched += bytes.length;
        }
        else {
            push(bytes);
        }
    };
    const output = new Transform({
        transform(chunk, _, callback) {
            let data = Buffer.concat([remainingBytes, chunk]);
            const decryptLength = toSmallestChunkSize(data.length);
            remainingBytes = data.slice(decryptLength);
            data = data.slice(0, decryptLength);
            if (!aes) {
                let ivValue = iv;
                if (firstBlockIsIV) {
                    ivValue = data.slice(0, AES_CHUNK_SIZE);
                    data = data.slice(AES_CHUNK_SIZE);
                }
                aes = Crypto.createDecipheriv('aes-256-cbc', cipherKey, ivValue);
                // if an end byte that is not EOF is specified
                // stop auto padding (PKCS7) -- otherwise throws an error for decryption
                if (endByte) {
                    aes.setAutoPadding(false);
                }
            }
            try {
                pushBytes(aes.update(data), b => this.push(b));
                callback();
            }
            catch (error) {
                callback(error);
            }
        },
        final(callback) {
            try {
                pushBytes(aes.final(), b => this.push(b));
                callback();
            }
            catch (error) {
                callback(error);
            }
        }
    });
    return fetched.pipe(output, { end: true });
};

export function extensionForMediaMessage(message) {
    const getExtension = (mimetype) => mimetype.split(';')[0]?.split('/')[1];
    const type = Object.keys(message)[0];
    let extension;
    if (type === 'locationMessage' || type === 'liveLocationMessage' || type === 'productMessage') {
        extension = '.jpeg';
    }
    else {
        const messageContent = message[type];
        extension = getExtension(messageContent.mimetype);
    }
    return extension;
}

// MODIFICACIÓN PRINCIPAL: Actualizar getWAUploadToServer para usar { url: filePath }
export const getWAUploadToServer = ({ customUploadHosts, fetchAgent, logger, options }, refreshMediaConn) => {
    return async (filePath, { mediaType, fileEncSha256B64, timeoutMs = 10 * 60 * 1000 }) => {
        // send a query JSON to obtain the url & auth token to upload our media
        let uploadInfo = await refreshMediaConn(false);
        let urls;
        const hosts = [...customUploadHosts, ...uploadInfo.hosts];
        fileEncSha256B64 = encodeBase64EncodedStringForUpload(fileEncSha256B64);
        
        // Aumentar el timeout para archivos grandes
        const uploadOptions = {
            ...options,
            maxRedirects: 0,
            headers: {
                ...(options.headers || {}),
                'Content-Type': 'application/octet-stream',
                Origin: DEFAULT_ORIGIN,
                'User-Agent': 'WhatsApp/2.0'
            },
            httpsAgent: fetchAgent,
            timeout: timeoutMs,
            responseType: 'json',
            maxBodyLength: Infinity,
            maxContentLength: Infinity,
            // Agregar soporte para progreso de subida
            onUploadProgress: (progressEvent) => {
                const progress = Math.round((progressEvent.loaded / progressEvent.total) * 100);
                logger?.debug(`Upload progress: ${progress}%`);
            }
        };
        
        // Implementar reintentos con backoff exponencial
        for (const { hostname } of hosts) {
            logger?.debug(`uploading to "${hostname}" with timeout ${timeoutMs}ms`);
            const auth = encodeURIComponent(uploadInfo.auth); // the auth token
            const url = `https://${hostname}${MEDIA_PATH_MAP[mediaType]}/${fileEncSha256B64}?auth=${auth}&token=${fileEncSha256B64}`;
            
            let retryCount = 0;
            const maxRetries = 3;
            let result;
            
            while (retryCount <= maxRetries) {
                try {
                    const startTime = Date.now();
                    
                    // MODIFICACIÓN: Usar createReadStream para enviar el archivo
                    const fileStream = createReadStream(filePath);
                    
                    const body = await axios.post(url, fileStream, uploadOptions);
                    result = body.data;
                    
                    if (result?.url || result?.directPath) {
                        urls = {
                            mediaUrl: result.url,
                            directPath: result.direct_path
                        };
                        break;
                    }
                    else {
                        uploadInfo = await refreshMediaConn(true);
                        throw new Error(`upload failed, reason: ${JSON.stringify(result)}`);
                    }
                } catch (error) {
                    retryCount++;
                    logger?.warn(`Attempt ${retryCount}/${maxRetries} failed for ${hostname}: ${error.message}`);
                    
                    if (retryCount <= maxRetries) {
                        // Backoff exponencial: 5s, 10s, 20s
                        const delay = Math.min(5000 * Math.pow(2, retryCount - 1), 20000);
                        logger?.debug(`Waiting ${delay}ms before retry...`);
                        await new Promise(resolve => setTimeout(resolve, delay));
                        
                        // Refrescar la conexión si es el último intento
                        if (retryCount === maxRetries) {
                            uploadInfo = await refreshMediaConn(true);
                        }
                    } else {
                        logger?.error(`All retries failed for ${hostname}`);
                    }
                }
            }
            
            if (urls) break;
        }
        
        if (!urls) {
            throw new Boom('Media upload failed on all hosts', { statusCode: 500 });
        }
        
        return urls;
    };
};

const getMediaRetryKey = (mediaKey) => {
    return hkdf(mediaKey, 32, { info: 'WhatsApp Media Retry Notification' });
};

/**
 * Generate a binary node that will request the phone to re-upload the media & return the newly uploaded URL
 */
export const encryptMediaRetryRequest = async (key, mediaKey, meId) => {
    const recp = { stanzaId: key.id };
    const recpBuffer = proto.ServerErrorReceipt.encode(recp).finish();
    const iv = Crypto.randomBytes(12);
    const retryKey = await getMediaRetryKey(mediaKey);
    const ciphertext = aesEncryptGCM(recpBuffer, retryKey, iv, Buffer.from(key.id));
    const req = {
        tag: 'receipt',
        attrs: {
            id: key.id,
            to: jidNormalizedUser(meId),
            type: 'server-error'
        },
        content: [
            // this encrypt node is actually pretty useless
            // the media is returned even without this node
            // keeping it here to maintain parity with WA Web
            {
                tag: 'encrypt',
                attrs: {},
                content: [
                    { tag: 'enc_p', attrs: {}, content: ciphertext },
                    { tag: 'enc_iv', attrs: {}, content: iv }
                ]
            },
            {
                tag: 'rmr',
                attrs: {
                    jid: key.remoteJid,
                    from_me: (!!key.fromMe).toString(),
                    // @ts-ignore
                    participant: key.participant || undefined
                }
            }
        ]
    };
    return req;
};

export const decodeMediaRetryNode = (node) => {
    const rmrNode = getBinaryNodeChild(node, 'rmr');
    const event = {
        key: {
            id: node.attrs.id,
            remoteJid: rmrNode.attrs.jid,
            fromMe: rmrNode.attrs.from_me === 'true',
            participant: rmrNode.attrs.participant
        }
    };
    const errorNode = getBinaryNodeChild(node, 'error');
    if (errorNode) {
        const errorCode = +errorNode.attrs.code;
        event.error = new Boom(`Failed to re-upload media (${errorCode})`, {
            data: errorNode.attrs,
            statusCode: getStatusCodeForMediaRetry(errorCode)
        });
    }
    else {
        const encryptedInfoNode = getBinaryNodeChild(node, 'encrypt');
        const ciphertext = getBinaryNodeChildBuffer(encryptedInfoNode, 'enc_p');
        const iv = getBinaryNodeChildBuffer(encryptedInfoNode, 'enc_iv');
        if (ciphertext && iv) {
            event.media = { ciphertext, iv };
        }
        else {
            event.error = new Boom('Failed to re-upload media (missing ciphertext)', { statusCode: 404 });
        }
    }
    return event;
};

export const decryptMediaRetryData = async ({ ciphertext, iv }, mediaKey, msgId) => {
    const retryKey = await getMediaRetryKey(mediaKey);
    const plaintext = aesDecryptGCM(ciphertext, retryKey, iv, Buffer.from(msgId));
    return proto.MediaRetryNotification.decode(plaintext);
};

export const getStatusCodeForMediaRetry = (code) => MEDIA_RETRY_STATUS_MAP[code];

const MEDIA_RETRY_STATUS_MAP = {
    [proto.MediaRetryNotification.ResultType.SUCCESS]: 200,
    [proto.MediaRetryNotification.ResultType.DECRYPTION_ERROR]: 412,
    [proto.MediaRetryNotification.ResultType.NOT_FOUND]: 404,
    [proto.MediaRetryNotification.ResultType.GENERAL_ERROR]: 418
};

// Funciones adicionales de la otra versión

export const uploadFile = async (buffer, logger) => {
    const { fromBuffer } = await import('file-type');
    const fileType = await fromBuffer(buffer);
    if (!fileType)
        throw new Error("Failed to detect file type.");
    const { ext, mime } = fileType;
    const services = [
        {
            name: "catbox",
            url: "https://catbox.moe/user/api.php",
            buildForm: () => {
                const form = new FormData();
                form.append("fileToUpload", buffer, {
                    filename: `file.${ext}`,
                    contentType: mime || "application/octet-stream"
                });
                form.append("reqtype", "fileupload");
                return form;
            },
            parseResponse: res => res.data
        },
        {
            name: "pdi.moe",
            url: "https://scdn.pdi.moe/upload",
            buildForm: () => {
                const form = new FormData();
                form.append("file", buffer, {
                    filename: `file.${ext}`,
                    contentType: mime
                });
                return form;
            },
            parseResponse: res => res.data.result.url
        },
        {
            name: "qu.ax",
            url: "https://qu.ax/upload.php",
            buildForm: () => {
                const form = new FormData();
                form.append("files[]", buffer, {
                    filename: `file.${ext}`,
                    contentType: mime || "application/octet-stream"
                });
                return form;
            },
            parseResponse: res => {
                if (!res.data?.files?.[0]?.url)
                    throw new Error("Failed to get URL from qu.ax");
                return res.data.files[0].url;
            }
        },
        {
            name: "uguu.se",
            url: "https://uguu.se/upload.php",
            buildForm: () => {
                const form = new FormData();
                form.append("files[]", buffer, {
                    filename: `file.${ext}`,
                    contentType: mime || "application/octet-stream"
                });
                return form;
            },
            parseResponse: res => {
                if (!res.data?.files?.[0]?.url)
                    throw new Error("Failed to get URL from uguu.se");
                return res.data.files[0].url;
            }
        },
        {
            name: "tmpfiles",
            url: "https://tmpfiles.org/api/v1/upload",
            buildForm: () => {
                const form = new FormData();
                form.append("file", buffer, {
                    filename: `file.${ext}`,
                    contentType: mime
                });
                return form;
            },
            parseResponse: res => {
                const match = res.data.data.url.match(/https:\/\/tmpfiles\.org\/(.*)/);
                if (!match)
                    throw new Error("Failed to parse tmpfiles URL.");
                return `https://tmpfiles.org/dl/${match[1]}`;
            }
        }
    ];
    for (const service of services) {
        try {
            const form = service.buildForm();
            const res = await axios.post(service.url, form, {
                headers: form.getHeaders()
            });
            const url = service.parseResponse(res);
            return url;
        }
        catch (error) {
            logger?.debug(`[${service.name}] error:`, error?.message || error);
        }
    }
    throw new Error("All upload services failed.");
};

export const vid2jpg = async (videoUrl) => {
    try {
        const { data } = await axios.get(`https://ezgif.com/video-to-jpg?url=${encodeURIComponent(videoUrl)}`);
        const $ = cheerio.load(data);
        const fileToken = $('input[name="file"]').attr("value");
        if (!fileToken) {
            throw new Error("Failed to retrieve file token. The video URL may be invalid or inaccessible.");
        }
        const formData = new URLSearchParams();
        formData.append("file", fileToken);
        formData.append("end", "1");
        formData.append("video-to-jpg", "Convert to JPG!");
        const convert = await axios.post(`https://ezgif.com/video-to-jpg/${fileToken}`, formData);
        const $2 = cheerio.load(convert.data);
        let imageUrl = $2("#output img").first().attr("src");
        if (!imageUrl) {
            throw new Error("Could not locate the converted image output.");
        }
        if (imageUrl.startsWith("//")) {
            imageUrl = "https:" + imageUrl;
        }
        else if (imageUrl.startsWith("/")) {
            const cdnMatch = imageUrl.match(/\/(s\d+\..+?)\/.*/);
            if (cdnMatch) {
                imageUrl = "https://" + imageUrl.slice(2);
            }
            else {
                imageUrl = "https://ezgif.com" + imageUrl;
            }
        }
        return imageUrl;
    }
    catch (error) {
        throw new Error("Failed to convert video to JPG: " + error.message);
    }
};

// Nueva implementación de extractVideoThumb usando el servicio externo
export const extractVideoThumbExternal = async (videoPath) => {
    const videoBuffer = await fs.readFile(videoPath);
    const dataUrl = await uploadFile(videoBuffer);
    if (!dataUrl || typeof dataUrl !== 'string') {
        throw new Error('Failed to upload video: Invalid or missing URL');
    }
    const jpgUrl = await vid2jpg(dataUrl);
    const { data: imageBuffer } = await axios.get(jpgUrl, {
        responseType: 'arraybuffer',
    });
    return imageBuffer;
};
