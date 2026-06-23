const crypto = require('crypto');
const axios = require('axios');

const APIKEY = process.env.APIKEY;
const SECRET = process.env.SECRET;

if (!(APIKEY || SECRET)) {
    console.error('APIKEY and SECRET environment variables must be set');
    process.exit(1);
}

const getEnvAsInt = (key, defaultValue) => {
    const value = process.env[key];
    return value !== undefined ? parseInt(value, 10) : defaultValue;
};

const TRANSIT_TIME_BUCKET = getEnvAsInt("TRANSIT_TIME_BUCKET", 60);
const TRANSIT_KEY_LENGTH = getEnvAsInt("TRANSIT_KEY_LENGTH", 60);
const HOST = process.env.HOST || "0.0.0.0";
const PORT = getEnvAsInt("PORT", 8080);


function generateAuthHeader(token) {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = crypto.createHmac('sha512', token).update(timestamp).digest('hex');
    return `Signature=${signature},timestamp=${timestamp}`;
}

async function transitDecrypt(ciphertext) {
    const epoch = Math.floor(Date.now() / (1000 * TRANSIT_TIME_BUCKET));
    const hash = crypto.createHash('sha256');
    hash.update(`${epoch}.${APIKEY}.${SECRET}`);
    const aesKey = hash.digest().slice(0, TRANSIT_KEY_LENGTH);

    const bufferCiphertext = Buffer.from(ciphertext, 'base64');
    if (bufferCiphertext.length < 12 + 16) {
        throw new Error('Ciphertext is too short');
    }

    const iv = bufferCiphertext.slice(0, 12); // First 12 bytes
    const authTag = bufferCiphertext.slice(bufferCiphertext.length - 16); // Last 16 bytes
    const encryptedData = bufferCiphertext.slice(12, bufferCiphertext.length - 16); // Data in between

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag); // Set the authentication tag

    let decrypted;
    try {
        decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    } catch (err) {
        throw new Error('Decryption failed: ' + err.message);
    }

    return JSON.parse(decrypted.toString());
}

async function getCipher() {
    const headers = {
        'accept': 'application/json',
        'Authorization': `Bearer ${generateAuthHeader(APIKEY)}`,
    };
    const params = {
        table_name: 'default',
    };
    const response = await axios.get(`http://${HOST}:${PORT}/get-table`, {params, headers});  // noqa: HttpUrlsUsage
    if (response.status !== 200) {
        throw new Error(response.data);
    }
    return response.data.detail;
}

async function main() {
    try {
        const ciphertext = await getCipher();
        const result = await transitDecrypt(ciphertext);
        console.log(result);
    } catch (error) {
        console.error(error);
    }
}

main();
