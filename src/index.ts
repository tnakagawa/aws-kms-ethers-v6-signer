import {
  KMSClient,
  KMSClientConfig,
  GetPublicKeyCommand,
  SignCommand,
} from "@aws-sdk/client-kms";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import {
  AbstractSigner,
  assert,
  assertArgument,
  Authorization,
  AuthorizationRequest,
  BytesLike,
  copyRequest,
  dataLength,
  getAddress,
  getBigInt,
  getBytes,
  hashAuthorization,
  hashMessage,
  keccak256,
  N,
  Provider,
  recoverAddress,
  resolveAddress,
  resolveProperties,
  Signature,
  SignatureLike,
  Signer,
  toBeHex,
  toBigInt,
  Transaction,
  TransactionLike,
  TransactionRequest,
  TypedDataDomain,
  TypedDataEncoder,
  TypedDataField,
} from "ethers";

/**
 * A Signer implementation that uses AWS KMS to sign messages and transactions.
 *
 * The signer retrieves the public key from AWS KMS to compute the Ethereum address
 */
export class AwsKmsSigner extends AbstractSigner {
  // AWS KMS Key ID or ARN
  private keyId: string;
  // AWS KMS client configuration
  private config: KMSClientConfig;
  // AWS KMS client instance
  private kmsClient: KMSClient;
  // Cached Ethereum address derived from the KMS public key
  address!: string;

  /**
   * Creates a new AwsKmsSigner instance.
   *
   * @param keyId - The AWS KMS Key ID or ARN to use for signing
   * @param config - Optional AWS KMS client configuration
   * @param provider - Optional ethers.js Provider to use for resolving ENS names and addresses
   */
  constructor(keyId: string, config?: KMSClientConfig, provider?: Provider) {
    super(provider);
    this.keyId = keyId;
    this.config = config || {};
    this.kmsClient = new KMSClient(this.config);
  }

  /**
   * Retrieves the Ethereum address associated with the AWS KMS key. This is derived from the public key retrieved from AWS KMS. The address is cached after the first retrieval for efficiency.
   *
   * @returns A promise that resolves to the Ethereum address as a string
   */
  async getAddress(): Promise<string> {
    // If the address is already cached, return it
    if (!this.address) {
      // Retrieve the public key from AWS KMS
      const command = new GetPublicKeyCommand({
        KeyId: this.keyId,
      });
      // Send the command to AWS KMS and get the response
      const response = await this.kmsClient.send(command);
      // Extract the public key from the response
      const publicKey = response.PublicKey;
      // If the public key is not available, throw an error
      if (!publicKey) {
        throw new Error("Failed to retrieve public key from AWS KMS");
      }
      // Parse the public key using ASN.1 to extract the EC public key
      const ecPublicKey = AsnConvert.parse(
        Buffer.from(publicKey),
        SubjectPublicKeyInfo,
      ).subjectPublicKey;
      // Compute the Ethereum address by taking the keccak256 hash of the public key (excluding the first byte) and taking the last 20 bytes of the hash
      // https://ethereum.github.io/yellowpaper/paper.pdf - Appendix F. Signing Transactions -  Ethereum address A(pr) (a 160-bit value)
      // https://eips.ethereum.org/EIPS/eip-55 - Ethereum address checksum
      this.address = getAddress(
        "0x" +
          keccak256(
            new Uint8Array(ecPublicKey.slice(1, ecPublicKey.byteLength)),
          ).slice(-40),
      );
    }
    return this.address;
  }

  /**
   * Connects the signer to a provider.
   *
   * @param provider - An ethers.js Provider to connect to
   * @returns A new Signer instance connected to the provided provider
   *
   * @note https://github.com/ethers-io/ethers.js/blob/b746c3cf6cd191e2357fa55751696676ffda060e/src.ts/wallet/base-wallet.ts#L71
   */
  connect(provider: Provider): Signer {
    return new AwsKmsSigner(this.keyId, this.config, provider);
  }

  /**
   * Signs a transaction with the AWS KMS key.
   *
   * @param tx - The transaction to sign
   * @returns A promise that resolves to the signed transaction as a string
   *
   * @note https://github.com/ethers-io/ethers.js/blob/b746c3cf6cd191e2357fa55751696676ffda060e/src.ts/wallet/base-wallet.ts#L75
   */
  async signTransaction(tx: TransactionRequest): Promise<string> {
    tx = copyRequest(tx);

    // Replace any Addressable or ENS name with an address
    const { to, from } = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this) : undefined,
      from: tx.from ? resolveAddress(tx.from, this) : undefined,
    });

    if (to != null) {
      tx.to = to;
    }
    if (from != null) {
      tx.from = from;
    }

    if (tx.from != null) {
      assertArgument(
        getAddress(<string>tx.from) === (await this.getAddress()),
        "transaction from address mismatch",
        "tx.from",
        tx.from,
      );
      delete tx.from;
    }

    // Build the transaction
    const btx = Transaction.from(<TransactionLike<string>>tx);
    btx.signature = await this._sign(btx.unsignedHash);

    return btx.serialized;
  }

  /**
   * Signs a message with the AWS KMS key.
   *
   * @param message - The message to sign, which can be a string or a Uint8Array
   * @returns A promise that resolves to the signed message as a string
   *
   * @note https://github.com/ethers-io/ethers.js/blob/b746c3cf6cd191e2357fa55751696676ffda060e/src.ts/wallet/base-wallet.ts#L109
   */
  async signMessage(message: string | Uint8Array): Promise<string> {
    return (await this._sign(hashMessage(message))).serialized;
  }

  /**
   * Signs an authorization request with the AWS KMS key. The authorization request is first resolved to ensure that any ENS names are converted to addresses, and then the resulting data is hashed and signed.
   *
   * @param auth - The authorization request to sign, which includes the address, nonce, and chainId
   * @returns A promise that resolves to the signed authorization, which includes the address, nonce, chainId, and signature
   *
   * @note https://github.com/ethers-io/ethers.js/blob/b746c3cf6cd191e2357fa55751696676ffda060e/src.ts/wallet/base-wallet.ts#L116
   */
  async authorize(auth: AuthorizationRequest): Promise<Authorization> {
    auth = Object.assign({}, auth, {
      address: await resolveAddress(auth.address, this),
    });
    auth = await this.populateAuthorization(auth);

    assertArgument(
      typeof auth.address === "string",
      "invalid address for authorizeSync",
      "auth.address",
      auth,
    );

    const signature = await this._sign(hashAuthorization(auth));
    return Object.assign(
      {},
      {
        address: getAddress(auth.address),
        nonce: getBigInt(auth.nonce || 0),
        chainId: getBigInt(auth.chainId || 0),
      },
      { signature },
    );
  }

  /**
   * Signs typed data with the AWS KMS key. The typed data is first resolved to ensure that any ENS names are converted to addresses, and then the resulting data is hashed and signed.
   *
   * @param domain - The domain separator for the typed data, which includes the name, version, chainId, and verifyingContract
   * @param types - The type definitions for the typed data, which is a mapping of type names to arrays of field definitions
   * @param value - The actual data to sign, which is a mapping of field names to values
   * @returns A promise that resolves to the signed typed data as a string
   *
   * @note https://github.com/ethers-io/ethers.js/blob/b746c3cf6cd191e2357fa55751696676ffda060e/src.ts/wallet/base-wallet.ts#L138
   */
  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    // `ethers` typings use `any` here for the value mapping.
    // This is intentional and matches the abstract signer interface, so we suppress the lint warning.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    value: Record<string, any>,
  ): Promise<string> {
    // Populate any ENS names
    const populated = await TypedDataEncoder.resolveNames(
      domain,
      types,
      value,
      async (name: string) => {
        // @TODO: this should use resolveName; addresses don't
        //        need a provider

        assert(
          this.provider != null,
          "cannot resolve ENS names without a provider",
          "UNSUPPORTED_OPERATION",
          {
            operation: "resolveName",
            info: { name },
          },
        );

        const address = await this.provider.resolveName(name);
        assert(address != null, "unconfigured ENS name", "UNCONFIGURED_NAME", {
          value: name,
        });

        return address;
      },
    );

    return (
      await this._sign(
        TypedDataEncoder.hash(populated.domain, types, populated.value),
      )
    ).serialized;
  }

  /**
   * Internal method to sign a digest with the AWS KMS key.
   * This method sends a SignCommand to AWS KMS with the specified digest and retrieves the signature. The signature is then parsed from ASN.1 format and converted to the format expected by Ethereum, including handling low S values and computing the recovery parameter (v) based on the recovered address.
   *
   * @param digest - The digest to sign, which must be a 32-byte value (e.g., the hash of a message or transaction)
   * @returns A promise that resolves to the signature in the format expected by Ethereum, including r, s, and v components
   */
  private async _sign(digest: BytesLike): Promise<Signature> {
    assertArgument(
      dataLength(digest) === 32,
      "invalid digest length",
      "digest",
      digest,
    );
    // Send the SignCommand to AWS KMS with the specified digest and signing parameters
    const command = new SignCommand({
      KeyId: this.keyId,
      Message: getBytes(digest),
      SigningAlgorithm: "ECDSA_SHA_256",
      MessageType: "DIGEST",
    });

    // Retrieve the signature from AWS KMS
    const response = await this.kmsClient.send(command);
    const signature = response.Signature;

    // If the signature is not available, throw an error
    if (!signature) {
      throw new Error("Failed to sign message with AWS KMS");
    }

    // Parse the signature from ASN.1 format to extract the r and s values
    const ecdsaSig = AsnConvert.parse(Buffer.from(signature), ECDSASigValue);

    // Handle low S values by ensuring that s is less than or equal to N/2.
    // If s is greater than N/2, it is replaced with N - s to ensure that the signature is in canonical form, which is required by Ethereum.
    // https://ethereum.github.io/yellowpaper/paper.pdf - Appendix F. Signing Transactions
    let s = toBigInt(new Uint8Array(ecdsaSig.s));
    const HALF = N >> 1n;
    if (s > HALF) {
      s = N - s;
    }

    // Construct the signature object with r, s, and a default v value of 0x1b (27 in decimal).
    // The r and s values are converted to hexadecimal format with appropriate padding.
    const sig: SignatureLike = {
      r: toBeHex(toBigInt(new Uint8Array(ecdsaSig.r))),
      s: toBeHex(s, 32),
      v: 0x1b,
    };

    // Compute the recovery parameter (v) by recovering the address from the signature and comparing it to the signer's address. If they do not match, set v to 0x1c.
    const recover = recoverAddress(digest, {
      r: sig.r,
      s: sig.s,
      v: sig.v,
    });
    // Retrieve the signer's address from AWS KMS (this will be cached after the first retrieval)
    const address = await this.getAddress();
    // If the recovered address does not match the signer's address, set v to 0x1c (28 in decimal) to indicate that the signature is valid but the recovery parameter is different.
    if (address.toLowerCase() !== recover.toLowerCase()) {
      sig.v = 0x1c;
    }

    return Signature.from(sig);
  }
}
