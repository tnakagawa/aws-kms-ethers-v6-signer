# aws-kms-ethers-v6-signer

A signer implementation for ethers.js v6 that uses AWS Key Management Service (KMS) for secure cryptographic signing operations.

## Installation

```bash
npm install @tnaka-dev/aws-kms-ethers-v6-signer
```

## Usage

### Create AwsKmsSigner

```typescript
import { ethers } from "ethers";
import { KMSClientConfig } from "@aws-sdk/client-kms";
import { AwsKmsSigner } from "@tnaka-dev/aws-kms-ethers-v6-signer";

const keyId = "<your AWS KMS key ID>"; // Replace with your actual AWS KMS key ID
const config = {
region: "<your AWS region>", // Replace with your actual AWS region
credentials: {
    accessKeyId: "<your AWS access key ID>", // Replace with your actual AWS access key ID
    secretAccessKey: "<your AWS secret access key>", // Replace with your actual AWS secret access key
},
} as KMSClientConfig;
// Create the signer
const signer = new AwsKmsSigner(keyId, config, provider);
// Connect the signer to the provider
const provider = new ethers.JsonRpcProvider("<your Ethereum JSON-RPC node URL>"); // Replace with your actual Ethereum JSON-RPC node URL
const connectedSigner = signer.connect(provider);
```

### getAddress

```typescript
// Address
const address = await signer.getAddress();
console.log("Address:", address);
```

### signMessage

```typescript
// Sign a message
const message = "Hello, AWS KMS Signer!";
const signature = await signer.signMessage(message);
console.log(
  "signMessage verification:",
  ethers.verifyMessage(message, signature) === address,
);
```

### sendTransaction

```typescript
// Sign a transaction
const toAddress = "<target Ethereum address>"; // Replace with the actual target Ethereum address
const tx = await connectedSigner.sendTransaction({
  to: toAddress,
  value: ethers.parseEther("0.01"),
});
const receipt = await tx.wait();
console.log("Transaction:", receipt?.status === 1 ? "Success" : "Failure");
```

### Contract call

```typescript
const toAddress = "<target Ethereum address>"; // Replace with the actual target Ethereum address
const contract = new ethers.Contract(
  "<target ERC20 contract address>", // Replace with the actual target ERC20 contract address
  [
    "function decimals() public view returns (uint8)",
    "function transfer(address to, uint256 value) external returns (bool)",
    "function balanceOf(address account) external view returns (uint256)",
  ],
  connectedSigner,
);
const decimals = await contract.decimals();
const tx = await contract.transfer(
  toAddress,
  ethers.parseUnits("100", decimals),
);
const receipt = await tx.wait();
console.log("ERC20 Transfer:", receipt?.status === 1 ? "Success" : "Failure");
console.log(
  "toAddress amount:",
  ethers.formatUnits(await contract.balanceOf(toAddress), decimals),
);
```

### signTypedData

Example: Signing typed data for ERC20Permit (ERC-2612) using @openzeppelin/contracts

```typescript
const contractAddress = "<target ERC20Permit(ERC-2612) contract address>"; // Replace with the actual target ERC20Permit(ERC-2612) contract address
const contractForView = new ethers.Contract(
  contractAddress,
  [
    "function eip712Domain() public view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] memory extensions)",
    "function decimals() public view returns (uint8)",
    "function nonces(address owner) public view returns (uint256)",
  ],
  provider,
);
// domain
const eip712Domain = await contractForView.eip712Domain();
const domain = {
  name: eip712Domain.name, // domain name
  version: eip712Domain.version, // domain version
  verifyingContract: eip712Domain.verifyingContract, // contract address
  chainId: eip712Domain.chainId, // chain ID
};
// types and value for permit
const TYPES = {
  Permit: [
    { name: "owner", type: "address" },
    { name: "spender", type: "address" },
    { name: "value", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};
// value for permit
const owner = await signer.getAddress();
const nonce = await contractForView.nonces(owner);
const decimals = await contractForView.decimals();
const spender = "<target Ethereum address>"; // Replace with the actual target Ethereum address
const value = {
  owner: owner,
  spender: spender,
  value: ethers.parseUnits("1", decimals),
  nonce: nonce,
  deadline: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
};
// sign typed data
const signature = await signer.signTypedData(domain, TYPES, value);
const sign = ethers.Signature.from(signature);
// send permit transaction
const contract = new ethers.Contract(
  contractAddress,
  [
    "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public",
  ],
  otherConnectedSigner,
);
const tx = await contract.permit(
  value.owner,
  value.spender,
  value.value,
  value.deadline,
  sign.v,
  sign.r,
  sign.s,
);
const receipt = await tx.wait();
console.log(
  "Permit Transaction:",
  receipt?.status === 1 ? "Success" : "Failure",
);
```

### authorize

Example: EIP-7702: Set Code for EOAs

```typescript
const delegateContractAddress = "<>target delegate contract address>"; // Replace with the actual target delegate contract address

// address
const address = await connectedSigner.getAddress();
// code
const code = await ethers.provider.getCode(address);
if (code === "0x") {
  // nonce
  const nonce = await connectedSigner.getNonce();
  // authorize
  const auth = await connectedSigner.authorize({
    address: delegateContractAddress,
    nonce: nonce + 1,
  });
  // send transaction with authorization
  const tx = await connectedSigner.sendTransaction({
    to: address,
    type: 4,
    authorizationList: [auth],
  });
  const receipt = await tx.wait();
  console.log(
    "Authorization Transaction:",
    receipt?.status === 1 ? "Success" : "Failure",
  );
} else {
  console.log("There is already code at this address.");
}
```

## Prerequisites

- AWS KMS key
  - Key spec
    - ECC_SECG_P256K1 (secp256k1)
  - Action
    - kms:Sign
    - kms:GetPublicKey

## Constructor

`new AwsKmsSigner(keyId, config?, provider?)`

Creates a new AwsKmsSigner instance.

- `keyId`: AWS KMS Key ID or ARN
- `config`: Optional AWS KMS client configuration
- `provider`: Optional ethers.js Provider



## License

MIT