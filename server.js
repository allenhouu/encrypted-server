const express = require('express');
const cors = require('cors')
const bodyParser = require("body-parser");
const crypto = require("crypto");
const user = [];
const admin = [{
    user: 'Mr. Goldstein',
    hash: 'ff5de730fa61e4b9d3ec2298efdce03e24240fb00d45f0d21f4644cda8c85ac4864091d93eefbfbb3b44b11fd6a8107d7f4675f9d4c93fc2503c27b9aa927dc8',
    salt: '19bc8c2e05f668a19bccc5262042af2b'
}];

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

app.post("/user", (req, res) => {
    const {username, password} = req.body;
    if (!username || !password) {
        return res.status(400).json({error: 'Username or Password is required'});
    }

    let decryptedUser = decryptData(username);
    let decryptedPassword = decryptedUser(password);

    for (let i = 0; i < user.length; i++) {
        if (user[i].username === decryptedUser) {
            return res.status(400).json({error: 'Username already in user'});
        }
    }

   createUser(user);
});

const decryptData = (user) => {
    // 1. Convert from encoded string to a buffer
    const buffer = Buffer.from(user, 'base64');

    // 2. Explicitly define padding and hash to match the Web Crypto API
    return crypto.privateDecrypt(
        {
            key: privateKey, // Your 2048-bit key from generateKeys()
            oaepHash: "sha256", // MUST BE THIS to match client's "SHA-256"
        },
        buffer
    ).toString("utf8");
};

function createUser(user, password) {
    const salt = crypto.randomBytes(16).toString('hex');

    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) throw err;

        const hash = derivedKey.toString('hex');

        //handle user creation here
        const newUser = {
            username: user,
            salt: salt,
            hash: hash,
            data: ""
        }
    })

}
