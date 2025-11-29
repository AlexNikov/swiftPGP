# SwiftPGP

Swift implementation of OpenPGP (RFC 4880) library, translated from ObjectivePGP.

## Status

✅ **Core Architecture Complete** - All major components implemented and tested

### Implemented Features

- ✅ **Packet Parsing**: Public Key, Secret Key, User ID, Signature, Literal Data, Public-Key Encrypted Session Key, Symmetrically Encrypted Integrity Protected Data
- ✅ **Key Management**: PGPKey, PGPKeyring, Key import/export
- ✅ **ASCII Armor**: Encoding/decoding with CRC24 checksum
- ✅ **Cryptography**:
  - ✅ CFB mode encryption/decryption (AES 128/192/256)
  - ✅ S2K (String-to-Key) algorithms
  - ✅ PKCS EMSA padding for RSA signatures
  - ✅ Hash algorithms: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160
  - ✅ Secure random data generation
- ✅ **Key Operations**:
  - ✅ Fingerprint calculation
  - ✅ Key ID extraction
  - ✅ Secret key decryption (AES encrypted keys)
- ✅ **Signature Support**:
  - ✅ Signature packet parsing
  - ✅ Signature subpacket parsing
  - ✅ Signature verification structure (requires RSA implementation)
- ✅ **Encryption/Decryption**:
  - ✅ High-level encrypt/decrypt API
  - ✅ Public-Key Encrypted Session Key packets
  - ✅ Symmetrically Encrypted Integrity Protected Data packets
  - ✅ Recipient key ID extraction from encrypted messages

### Pending Implementation

⚠️ **RSA Operations** - Requires OpenSSL or Security framework integration
- RSA encryption/decryption
- RSA signing/verification
- Full signature verification
- Data encryption/decryption

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/your-repo/swiftPGP.git", from: "1.0.0")
]
```

## Usage

### Reading Keys

```swift
import SwiftPGP

// Read keys from data
let keyData = Data(/* PGP key data */)
let keys = try SwiftPGP.readKeys(fromData: keyData)

// Read keys from file
let keys = try SwiftPGP.readKeys(fromPath: "~/.gnupg/pubring.gpg")
```

### Working with Keys

```swift
// Access key properties
let key = keys.first!
print("Key ID: \(key.keyID?.longIdentifier ?? "unknown")")
print("Fingerprint: \(key.fingerprint?.hexString ?? "unknown")")
print("Is Secret: \(key.isSecret)")

// Export key
let exported = try key.export(keyType: .public)
let armored = PGPArmor.armored(exported, as: .publicKey)
print(armored)
```

### Keyring Management

```swift
let keyring = PGPKeyring()

// Import keys
try keyring.import(keys: keys)

// Find key by ID
if let key = keyring.findKey("0x12345678") {
    // Use key
}

// Export keys
let exported = try keyring.exportKeys(of: .public)
```

### Generating Keys

```swift
import SwiftPGP

// Initialize generator with default settings (RSA 3072-bit)
let keyGen = PGPKeyGenerator()

// Generate key pair
if let key = keyGen.generate(for: "Alice <alice@example.com>", passphrase: "password123") {
    // Export Public Key
    let publicKeyData = try key.export(keyType: .public)
    let armoredPublic = PGPArmor.armored(publicKeyData, as: .publicKey)
    print(armoredPublic)
    
    // Export Secret Key
    let secretKeyData = try key.export(keyType: .secret)
    let armoredSecret = PGPArmor.armored(secretKeyData, as: .secretKey)
    print(armoredSecret)
}
```

### Verifying Signatures

```swift
// Verify signed message
let signedData = Data(/* signed message */)
let publicKeys = try SwiftPGP.readKeys(fromData: publicKeyData)

do {
    let isValid = try SwiftPGP.verify(signedData, using: publicKeys)
    print("Signature valid: \(isValid)")
} catch {
    print("Verification failed: \(error)")
}
```

### Encryption & Decryption

```swift
// Encrypt data with public keys
// Note: Requires RSA operations to be implemented for full functionality
let dataToEncrypt = "Secret message".data(using: .utf8)!
let publicKeys = try SwiftPGP.readKeys(fromData: publicKeyData)

do {
    let encryptedData = try SwiftPGP.encrypt(dataToEncrypt,
                                            addSignature: false,
                                            using: publicKeys)
    
    // Optionally convert to armored format
    let armored = PGPArmor.armored(encryptedData, as: .message)
    print(armored)
} catch {
    print("Encryption failed: \(error)")
}

// Decrypt data with secret keys
let secretKeys = try SwiftPGP.readKeys(fromData: secretKeyData)

do {
    let decryptedData = try SwiftPGP.decrypt(encryptedData,
                                           andVerifySignature: false,
                                           using: secretKeys,
                                           passphraseForKey: { key in
        // Return passphrase for encrypted secret keys
        return "your-passphrase"
    })
    
    let message = String(data: decryptedData, encoding: .utf8)
    print("Decrypted: \(message ?? "invalid")")
} catch {
    print("Decryption failed: \(error)")
}

// Get recipient key IDs from encrypted message
let recipientIDs = try SwiftPGP.recipientsKeyID(forMessage: encryptedData)
for keyID in recipientIDs {
    print("Recipient: \(keyID.longIdentifier)")
}
```

## Architecture

### Core Components

- **PGPPacket**: Base class for all PGP packets
- **PGPPacketFactory**: Factory for creating packets from binary data
- **PGPKey**: Represents a complete PGP key (public + secret)
- **PGPKeyring**: Manages a collection of keys

### Packet Types

- `PGPPublicKeyPacket`: Public key material
- `PGPSecretKeyPacket`: Secret key material (with S2K support)
- `PGPSignaturePacket`: Digital signatures
- `PGPUserIDPacket`: User identification
- `PGPLiteralPacket`: Literal data
- `PGPPublicKeyEncryptedSessionKeyPacket`: Public-key encrypted session key
- `PGPSymmetricallyEncryptedIntegrityProtectedDataPacket`: Symmetrically encrypted data

### Cryptographic Components

- `PGPCryptoCFB`: CFB mode encryption/decryption
- `PGPS2K`: String-to-Key algorithms
- `PGPPKCSEmsa`: PKCS EMSA padding
- `PGPCryptoUtils`: Cryptographic utilities (random data, key/block sizes)
- `PGPRSA`: RSA operations (implemented using OpenSSL)

## RSA Implementation Status

✅ **RSA operations are fully implemented** using OpenSSL integration.

The `PGPRSA` class provides:
- `publicEncrypt(_:withPublicKeyPacket:)` - Encrypt data with public key
- `privateDecrypt(_:withSecretKeyPacket:)` - Decrypt data with private key
- `privateEncrypt(_:withSecretKeyPacket:)` - Sign data (private key encryption)
- `publicDecrypt(_:withPublicKeyPacket:)` - Verify signature (public key decryption)
- `generateNewKeyMPIArray(bits:)` - Generate new RSA key pairs

### Integration

This library uses [OpenSSL](https://github.com/krzyzanowskim/OpenSSL) package via Swift Package Manager.

## Testing

Run tests:
```bash
swift test
```

## Project Structure

```
swiftPGP/
├── Sources/
│   └── SwiftPGP/
│       ├── PGPTypes.swift          # Types and enums
│       ├── PGPFoundation.swift     # Utilities
│       ├── PGPPacket.swift         # Base packet class
│       ├── PGPPacketFactory.swift  # Packet factory
│       ├── PGPKey*.swift           # Key classes
│       ├── PGPCrypto*.swift        # Cryptographic operations
│       └── SwiftPGP.swift          # Main API
└── Tests/
    └── SwiftPGPTests/
        └── *.swift                 # Test files
```

## License

This is a translation of ObjectivePGP library. Please refer to the original license.

## Contributing

Contributions are welcome! Areas that need work:
- Full encrypt/decrypt implementation details (e.g. MDC, other algorithms)
- Full sign implementation details
- Additional packet types (Trust, User Attribute)
- Compression support (ZLIB/ZIP)
- Performance optimizations

## Acknowledgments

Based on ObjectivePGP by Marcin Krzyżanowski.
