const express = require('express');
const cors = require('cors')
const bodyParser = require("body-parser");

const app = express();
app.use(cors({
    methods: ['GET', 'POST', 'PUT', 'DELETE'] // Specify allowed methods
}));

app.use(bodyParser.json());
const port = 3000;

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
})

app.get("/public_key", (req, res) => {
        res.status(200).json(publicKey);
});

const generateKeys = () => {
    const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Recommended key size for security
        publicKeyEncoding: {
            type: 'spki', // Recommended for public keys
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8', // Recommended for private keys
            format: 'pem',
        },
    });
    console.log('Private Key:', keys.privateKey);
    console.log('Public Key:', keys.publicKey);
    return keys;
}
let {publicKey, privateKey} = generateKeys();