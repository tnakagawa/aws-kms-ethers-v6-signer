import { AwsKmsSigner } from "../src/index";
import { mockClient } from "aws-sdk-client-mock";
import {
  Wallet,
  HDNodeWallet,
  SigningKey,
  Signature,
  Transaction,
  TypedDataDomain,
  TypedDataField,
  Provider,
  AuthorizationRequest,
  toBigInt,
  toBeHex,
  N,
} from "ethers";
import { BitString, Integer, ObjectIdentifier, Sequence } from "asn1js";
import { AlgorithmIdentifier, PublicKeyInfo } from "pkijs";
import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
} from "@aws-sdk/client-kms";

/**
 * Convert uncompressed secp256k1 public key (04 + X + Y)
 * into DER-encoded SubjectPublicKeyInfo using PKI.js
 */
function uncompressedToDerSPKI(uncompressedHex: string): Uint8Array {
  if (!uncompressedHex.startsWith("0x04") || uncompressedHex.length !== 132) {
    throw new Error(
      "Invalid uncompressed public key (must be 65 bytes starting with 0x04)",
    );
  }

  const publicKeyBytes = Buffer.from(uncompressedHex.slice(2), "hex");

  // ArrayBuffer view of the public key bytes for PKI.js
  const keyArrayBuffer = publicKeyBytes.buffer.slice(
    publicKeyBytes.byteOffset,
    publicKeyBytes.byteOffset + publicKeyBytes.byteLength,
  );

  // AlgorithmIdentifier
  const algorithm = new AlgorithmIdentifier({
    algorithmId: "1.2.840.10045.2.1", // id-ecPublicKey
    algorithmParams: new ObjectIdentifier({ value: "1.3.132.0.10" }), // secp256k1
  });

  // PublicKeyInfo
  const spki = new PublicKeyInfo({
    algorithm,
    subjectPublicKey: new BitString({ valueHex: keyArrayBuffer }),
  });

  return new Uint8Array(spki.toSchema().toBER(false));
}

/**
 * Convert ECDSA r and s (hex) into DER signature using asn1js.
 */
export function rsToDerWithAsn1js(rHex: string, sHex: string): Uint8Array {
  const r = trimAndSlice(Buffer.from(rHex.slice(2), "hex"));
  const s = trimAndSlice(Buffer.from(sHex.slice(2), "hex"));

  const rInt = new Integer({ valueHex: r });
  const sInt = new Integer({ valueHex: s });

  const seq = new Sequence({
    value: [rInt, sInt],
  });

  return new Uint8Array(seq.toBER(false));
}

/* ------------------------------
   Helpers
--------------------------------*/

function trimAndSlice(buf: Buffer): ArrayBuffer {
  // Trim leading zeros
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0x00) i++;
  const trimmed = buf.slice(i);

  // If the highest bit is set, prepend a zero byte to indicate it's positive
  const safe =
    trimmed[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed;

  return safe.buffer.slice(safe.byteOffset, safe.byteOffset + safe.byteLength);
}

/**
 * Tests for AwsKmsSigner
 */
describe("AwsKmsSigner", () => {
  const mockKMS = mockClient(KMSClient);
  const keyId = "test-key-id";
  const mockProvider = {
    resolveName: jest.fn(),
  } as unknown as Provider;
  let signer: AwsKmsSigner;
  let wallet: HDNodeWallet;
  let signKey: SigningKey;
  beforeEach(() => {
    // Reset mocks
    mockKMS.reset();

    signer = new AwsKmsSigner(keyId);
    wallet = Wallet.createRandom();
    wallet = wallet.connect(mockProvider);
    signKey = new SigningKey(wallet.privateKey);

    mockKMS.on(GetPublicKeyCommand).resolves({
      PublicKey: uncompressedToDerSPKI(signKey.publicKey),
    });
  });

  describe("getAddress", () => {
    it("normal: should return the correct address", async () => {
      const address = await signer.getAddress();
      expect(address).toBe(wallet.address);
    });
    it("normal: should cache the address", async () => {
      const address = await signer.getAddress();
      expect(address).toBe(wallet.address);
      const address2 = await signer.getAddress();
      expect(address2).toBe(address);
    });
    it("error: should throw an error when public key retrieval fails", async () => {
      mockKMS.on(GetPublicKeyCommand).resolves({});
      await expect(signer.getAddress()).rejects.toThrow(
        "Failed to retrieve public key from AWS KMS",
      );
    });
  });
  describe("connect", () => {
    it("normal: should connect to the provider", async () => {
      const connectedSigner = signer.connect(mockProvider);
      expect(signer.provider).toBeNull();
      expect(connectedSigner.provider).toBe(mockProvider);
    });
  });
  describe("signTransaction", () => {
    it("normal: should sign a transaction", async () => {
      const tx = {
        to: "0x000000000000000000000000000000000000dead",
        from: wallet.address,
        value: 0n,
      };
      const signTx = await wallet.signTransaction(tx);
      const stx = Transaction.from(signTx);
      if (!stx.signature) throw new Error("Signature is undefined");
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(stx.signature.r, stx.signature.s),
      });
      const signed = await signer.signTransaction(tx);
      expect(signed).toBe(signTx);
    });
    it("normal: should sign an empty transaction", async () => {
      const tx = {};
      const signTx = await wallet.signTransaction(tx);
      const stx = Transaction.from(signTx);
      if (!stx.signature) throw new Error("Signature is undefined");
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(stx.signature.r, stx.signature.s),
      });
      const signed = await signer.signTransaction(tx);
      expect(signed).toBe(signTx);
    });
    it("error: should throw an error when transaction from address mismatch", async () => {
      const tx = {
        to: "0x000000000000000000000000000000000000dead",
        from: "0x1111111111111111111111111111111111111111",
        value: 0n,
      };
      await expect(signer.signTransaction(tx)).rejects.toThrow(
        "transaction from address mismatch",
      );
    });
  });
  describe("signMessage", () => {
    it("normal: should sign a message", async () => {
      const sig = await wallet.signMessage("hello world");
      const signature = Signature.from(sig);
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(signature.r, signature.s),
      });
      const signed = await signer.signMessage("hello world");
      expect(signed).toBe(sig);
    });
  });
  describe("authorize", () => {
    it("normal: should authorize an authorization request", async () => {
      const authorizationRequest: AuthorizationRequest = {
        address: wallet.address,
        nonce: 10n,
        chainId: 1n,
      };
      const authorization = await wallet.authorize(authorizationRequest);
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(
          authorization.signature.r,
          authorization.signature.s,
        ),
      });
      const authorized = await signer.authorize(authorizationRequest);
      expect(authorized.address).toBe(authorizationRequest.address);
      expect(authorized.nonce).toBe(authorizationRequest.nonce);
      expect(authorized.chainId).toBe(authorizationRequest.chainId);
      expect(authorized.signature).toStrictEqual(authorization.signature);
    });
    it("normal: should authorize with zero nonce and chainId", async () => {
      const authorizationRequest: AuthorizationRequest = {
        address: wallet.address,
        nonce: 0n,
        chainId: 0n,
      };
      const authorization = await wallet.authorize(authorizationRequest);
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(
          authorization.signature.r,
          authorization.signature.s,
        ),
      });
      const authorized = await signer.authorize(authorizationRequest);
      expect(authorized.address).toBe(authorizationRequest.address);
      expect(authorized.nonce).toBe(authorizationRequest.nonce);
      expect(authorized.chainId).toBe(authorizationRequest.chainId);
      expect(authorized.signature).toStrictEqual(authorization.signature);
    });
  });
  describe("signTypedData", () => {
    it("normal: should sign typed data", async () => {
      const domain: TypedDataDomain = {
        name: "Test",
      };
      const types: Record<string, Array<TypedDataField>> = {
        Test: [{ name: "name", type: "string" }],
      };
      const value: Record<string, any> = {
        name: "hello world",
      };
      const sig = await wallet.signTypedData(domain, types, value);
      const signature = Signature.from(sig);
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(signature.r, signature.s),
      });
      const connectedSigner = signer.connect(mockProvider);
      const signed = await connectedSigner.signTypedData(domain, types, value);
      expect(signed).toBe(sig);
    });
    it("normal: should sign typed data with ENS resolving for verifyingContract", async () => {
      const domain: TypedDataDomain = {
        name: "test",
        verifyingContract: "test.verifyingContract",
      };
      const types: Record<string, Array<TypedDataField>> = {
        Test: [{ name: "name", type: "string" }],
      };
      const value: Record<string, any> = {
        name: "hello world",
      };
      (mockProvider.resolveName as jest.Mock).mockImplementation(
        async (ensName: string) => {
          if (ensName === domain.verifyingContract) {
            return "0x000000000000000000000000000000000000dead";
          }
          return null;
        },
      );
      const sig = await wallet.signTypedData(domain, types, value);
      const signature = Signature.from(sig);
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(signature.r, signature.s),
      });
      const connectedSigner = signer.connect(mockProvider);
      const signed = await connectedSigner.signTypedData(domain, types, value);
      expect(signed).toBe(sig);
    });
    it("error: should throw an error when provider is not connected", async () => {
      const domain: TypedDataDomain = {
        name: "test",
        verifyingContract: "test.verifyingContract",
      };
      const types: Record<string, Array<TypedDataField>> = {
        Test: [{ name: "name", type: "string" }],
      };
      const value: Record<string, any> = {
        name: "hello world",
      };
      await expect(signer.signTypedData(domain, types, value)).rejects.toThrow(
        "cannot resolve ENS names without a provider",
      );
    });
  });
  describe("_sign", () => {
    it("normal: should sign message with low s normalization", async () => {
      const sig = await wallet.signMessage("hello world");
      const signature = Signature.from(sig);
      let s = toBigInt(signature.s);
      if (s < N >> 1n) {
        s = N - s;
      }
      mockKMS.on(SignCommand).resolves({
        Signature: rsToDerWithAsn1js(signature.r, toBeHex(s)),
      });
      const signed = await signer.signMessage("hello world");
      expect(signed).toBe(sig);
    });
    it("error: should throw an error when KMS signing fails", async () => {
      mockKMS.on(SignCommand).resolves({});
      await expect(signer.signMessage("hello world")).rejects.toThrow(
        "Failed to sign message with AWS KMS",
      );
    });
  });
});
