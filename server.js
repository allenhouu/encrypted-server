const express = require('express');
const cors = require('cors')
const bodyParser = require("body-parser");
const crypto = require("crypto");
const users = [];
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
    const {encryptedUserName, encryptedPassword} = req.body;
    if (!encryptedUserName || !encryptedPassword) {
        return res.status(400).json({error: 'Username or Password is required'});
    }

    let decryptedUser = decryptData(encryptedUserName);
    let decryptedPassword = decryptData(encryptedPassword);

    for (let i = 0; i < users.length; i++) {
        if (users[i].username === decryptedUser) {
            return res.status(400).json({error: 'Username already in user'});
        }
    }
    res.status(200).json({success: 'Successfully created user'})
    createUser(decryptedUser, decryptedPassword);

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

        users.push(newUser);
    })
}

function verifyPassword(inputPassword, storedSalt, storedHash, actionOnSuccess, actionOnFail) {
    crypto.scrypt(inputPassword, storedSalt, 64, (err, derivedKey) => {
        if (err) throw err;

        const inputHash = derivedKey.toString('hex');

        // Compare the newly generated hash with the one stored in the database
        if(storedHash === inputHash) {
            actionOnSuccess();
        } else
            actionOnFail();
    });
}


app.put("/data", (req, res) => {
    const {encryptedUserName, encryptedPassword, encryptedData} = req.body;
    const user = req.query.user;

    if (!encryptedUserName || !encryptedPassword || !encryptedData || !user) {
        return res.status(400).json({error: "Invalid encrypted data provided"});
    }
    let decryptedUser = decryptData(encryptedUserName);
    let decryptedPassword = decryptData(encryptedPassword);
    let decryptedData = decryptData(encryptedData);

    let target = users.find(user => user.username === decryptedUser);

    if (!target) {
        return res.status(404).json({error: 'Target not found'});
    }

    let account = target;
    let isAdmin = false;

    for (let i = 0; i < admin.length; i++) {
        if (admin[i].user === decryptedUser)
        {
            isAdmin = true;
            account = admin[i];
            break;
        }
    }

    verifyPassword(decryptedPassword, account.salt, account.hash, () => {
        target.data = decryptedData;
        res.status(200).json({success: 'Successfully verified'});
    }, () => {
        res.status(400).json({error: 'Invalid credentials'});
    });
});

const urlSafeToBase64 = (urlSafeStr) => {
    // Add padding back for standard Base64 if needed
    let standardB64 = urlSafeStr.replace(/-/g, '+').replace(/_/g, '/');
    while (standardB64.length % 4) {
        standardB64 += '=';
    }
    return standardB64;
};

app.get("/data", (req, res) => {
    const {u, p} = req.body;
    let encryptedUserName = urlSafeToBase64(u);
    let encryptedPassword = urlSafeToBase64(p);

    if (!encryptedUserName || !encryptedPassword) {
        return res.status(400).json({error: "Invalid query parameters"})
    }
    let decryptedUser = decryptData(encryptedUserName);
    let decryptedPassword = decryptData(encryptedPassword);

    let target = users.find(user => user.username === decryptedUser);

    if (!target) {
        return res.status(404).json({error: "Target not found"});
    }
    let account = target;
    let isAdmin = false;

    for (let i = 0; i < admin.length; i++) {
        if (admin[i].user === decryptedUser)
        {
            isAdmin = true;
            account = admin[i];
            break;
        }
    }

    verifyPassword(decryptedPassword, account.salt, account.hash, () => {
        res.status(200).json({success: 'Successfully verified'});
    }, () => {
        res.status(400).json({error: 'Invalid credentials'});
    })
});