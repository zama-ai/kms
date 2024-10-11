const { createInstance } = require('fhevmjs');
const { Wallet } = require('ethers');

const PRIVATE_KEY = '0x7ec931411ad75a7c201469a385d6f18a325d4923f9f213bd882bbea87e160b67'; // User wallet private key
const CONTRACT_ADDRESS = '0xc8c9303Cd7F337fab769686B593B87DC3403E0ce'; // Contract address allowed on the ciphertext
const HANDLE = BigInt('0x59371e7af810e7ebd06ddd8d3b5d51d36b34fd2eeb9908f27d8d42442b970300'); // Ciphertext handle as BigInt

const reencrypt = async () => {
    const instance = await createInstance({ networkUrl: 'http://localhost:8545', gatewayUrl: 'http://localhost:7077' });
    const { publicKey, privateKey } = instance.generateKeypair();
    const eip712 = instance.createEIP712(publicKey, CONTRACT_ADDRESS);
    const signer = new Wallet(PRIVATE_KEY);
    const userAddress = await signer.getAddress()

    console.log('eip712.types:', eip712.types);
    const signature = await signer.signTypedData(eip712.domain, { Reencrypt: eip712.types.Reencrypt }, eip712.message);
    console.log('signature length:', signature.length);

    console.log('EIP712:', eip712);
    console.log('Public Key:', publicKey);
    console.log('Private Key:', privateKey);
    console.log('Signature:', signature);
    console.log('User Address:', userAddress);
    console.log('Contract Address:', CONTRACT_ADDRESS);
    console.log('Handle:', HANDLE);

    const value = await instance.reencrypt(
        HANDLE,
        privateKey,
        publicKey,
        signature.replace('0x', ''),
        CONTRACT_ADDRESS,
        userAddress,
    );
    console.log(value);
}

reencrypt();