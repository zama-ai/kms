const { ethers } = require('ethers');
const axios = require('axios');

// Example private key
const privateKey = '0x7ec931411ad75a7c201469a385d6f18a325d4923f9f213bd882bbea87e160b67';
const wallet = new ethers.Wallet(privateKey);

console.log('Signer address:', wallet.address);

// Define the EIP-712 domain
const domain = {
    name: 'Authorization token',
    version: '1',
    chainId: 9000,
    verifyingContract: '0xc8c9303Cd7F337fab769686B593B87DC3403E0ce'
};

// Define the types
const types = {
    Reencrypt: [
        { name: 'publicKey', type: 'bytes' }
    ]
};

// Define the message
const message = {
    publicKey: '0x97f272ccfef4026a1f3f0e0e879d514627b84e69'
};

async function main() {
    // Derive the EIP-712 signing hash.
    const messageHash = ethers.TypedDataEncoder.hash(domain, types, message);
    console.log('Message hash:', messageHash);

    // Sign the hash
    const signature = await wallet.signTypedData(domain, types, message);
    console.log('Signature:', signature);

    // Recover the address
    const recoveredAddress = ethers.verifyTypedData(domain, types, message, signature);
    console.log('Recovered address:', recoveredAddress);

    // Verify the signature
    const isMatchingAddress = recoveredAddress.toLowerCase() === wallet.address.toLowerCase();
    console.log('Recovered address matches wallet address:', isMatchingAddress);

    // Prepare the payload for the POST request
    const payload = {
        signature: signature.replace(/^0x/, ''),
        user_address: wallet.address.replace(/^0x/, ''),
        enc_key: '408d8cbaa51dece7f782fe04ba0b1c1d017b1088',
        ciphertext_handle: 'aa9f8f90ebf0fa8e30caee92f0b97e158f1ec659b363101d07beac9b0cc90200',
        eip712_verifying_contract: domain.verifyingContract.replace(/^0x/, ''),
    };

    // Send the POST request
    try {
        const response = await axios.post('http://127.0.0.1:7077/reencrypt', payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log('Server response:', response.data);
    } catch (error) {
        console.error('Error posting to server:', error);
    }
}

main().catch(console.error);
