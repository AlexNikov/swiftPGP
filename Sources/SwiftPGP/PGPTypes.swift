//  PGPTypes.swift
//  SwiftPGP

import Foundation

// MARK: - Constants

public let PGPUnknownLength: UInt32 = UInt32.max
public let PGPErrorDomain = "com.swiftpgp"

// MARK: - Error Types

public enum PGPError: Int, Error {
    case general = -1
    case passphraseRequired = 5
    case passphraseInvalid = 6
    /// Invalid signature. Signature is invalid or cannot be verified (eg. missing key)
    case invalidSignature = 7
    /// The message is not signed.
    case notSigned = 8
    /// Invalid PGP message. Invalid or corrupted data that can't be processed.
    case invalidMessage = 9
    case missingSignature = 10
    case notFound = 11
    // for check signature with rootCA
    case missingPublicKeySignature = 12
    case missingRootPublicKey = 13
    case invalidRootPublicKey = 14
    
    public var localizedDescription: String {
        switch self {
        case .general:
            return "General error"
        case .passphraseRequired:
            return "Passphrase required"
        case .passphraseInvalid:
            return "Invalid passphrase"
        case .invalidSignature:
            return "Invalid signature"
        case .notSigned:
            return "Message is not signed"
        case .invalidMessage:
            return "Invalid PGP message"
        case .missingSignature:
            return "Missing signature"
        case .notFound:
            return "Not found"
        case .missingPublicKeySignature:
            return "Missing public key signature"
        case .missingRootPublicKey:
            return "Missing root public key"
        case .invalidRootPublicKey:
            return "Invalid root public key"
        }
    }
}

// MARK: - Format Types

public enum PGPFormatType: Int {
    case unknown = 0
    case old = 1
    case new = 2
}

// MARK: - Header Packet Tag

public enum PGPHeaderPacketTag: UInt8 {
    case newFormat = 0x40
    case alwaysSet = 0x80
}

// MARK: - Packet Tag

public enum PGPPacketTag: UInt8 {
    case invalid = 0
    case publicKeyEncryptedSessionKey = 1
    case signature = 2
    case symmetricKeyEncryptedSessionKey = 3
    case onePassSignature = 4
    case secretKey = 5
    case publicKey = 6
    case secretSubkey = 7
    case compressedData = 8
    case symmetricallyEncryptedData = 9
    case marker = 10 // (Obsolete Literal Packet)
    case literalData = 11
    case trust = 12
    case userID = 13
    case publicSubkey = 14
    case userAttribute = 17
    case symmetricallyEncryptedIntegrityProtectedData = 18
    case modificationDetectionCode = 19
    case experimental1 = 60
    case experimental2 = 61
    case experimental3 = 62
    case experimental4 = 63
}

// MARK: - User Attribute Subpacket Type

public enum PGPUserAttributeSubpacketType: UInt8 {
    case unknown = 0x00
    case image = 0x01 // The only currently defined subpacket type is 1, signifying an image.
}

// MARK: - Public Key Algorithms

// 9.1.  Public-Key Algorithms
public enum PGPPublicKeyAlgorithm: UInt8 {
    case rsa = 1
    case rsaEncryptOnly = 2
    case rsaSignOnly = 3
    case elgamal = 16 // Elgamal (Encrypt-Only)
    case dsa = 17
    case ecdh = 18 // encrypt-only
    case ecdsa = 19 // sign-only
    case elgamalEncryptorSign = 20 // Deprecated ?
    case diffieHellman = 21 // TODO: Deprecated?
    case edDSA = 22 // sign-only
    case private1 = 100
    case private2 = 101
    case private3 = 102
    case private4 = 103
    case private5 = 104
    case private6 = 105
    case private7 = 106
    case private8 = 107
    case private9 = 108
    case private10 = 109
    case private11 = 110
}

// MARK: - Symmetric-Key Algorithms

// 9.2.  Symmetric-Key Algorithms
public enum PGPSymmetricAlgorithm: UInt8 {
    case plaintext = 0
    case idea = 1 // 8 bytes (64-bit) block size, key length: 2 bytes (16 bit)
    case tripleDES = 2 // 8 bytes (64-bit) block size
    case cast5 = 3 // aka CAST-128 is a symmetric block cipher with a block-size of 8 bytes (64bit) and a variable key-size of up to 16 bytes (128 bits).
    case blowfish = 4 // 8 bytes (64 bit) block size, key length: 16 bits (4-56 bits)
    case aes128 = 7 // 16 bytes (128 bit), key length 128 bit
    case aes192 = 8 // 16 bytes (128 bit), key length 192 bit
    case aes256 = 9 // 16 bytes (128 bit), key length 256 bit
    case twofish256 = 10 // 16 bytes (128 bit)
    case max
}

// MARK: - ECC Curve OID

// rfc4880bis 9.2.  ECC Curve OID
public enum PGPCurve: UInt8 {
    case p256 = 0
    case p384 = 1
    case p521 = 2
    case brainpoolP256r1 = 3
    case brainpoolP512r1 = 4
    case ed25519 = 5
    case curve25519 = 6
}

// MARK: - Hash Algorithms

// 9.4.  Hash Algorithms
public enum PGPHashAlgorithm: UInt8 {
    case unknown = 0
    case md5 = 1 // MD5  - deprecated
    case sha1 = 2 // SHA1 - required
    case ripemd160 = 3 // RIPEMD160
    case sha256 = 8 // SHA256
    case sha384 = 9 // SHA384
    case sha512 = 10 // SHA512
    case sha224 = 11 // SHA224
    case sha3_256 = 12 // SHA3-256
    case sha3_512 = 14 // SHA3-512
}

// MARK: - Signature Type

public enum PGPSignatureType: UInt8 {
    case binaryDocument = 0x00
    case canonicalTextDocument = 0x01
    case standalone = 0x02
    case genericCertificationUserIDandPublicKey = 0x10 // Self-Signature
    case personalCertificationUserIDandPublicKey = 0x11 // Self-Signature
    case casualCertificationUserIDandPublicKey = 0x12 // Self-Signature
    case positiveCertificationUserIDandPublicKey = 0x13 // Self-Signature
    case subkeyBinding = 0x18 // Self-Signature
    case primaryKeyBinding = 0x19
    case directlyOnKey = 0x1F // 0x1F: Signature directly on a key (key) - Self-Signature
    case keyRevocation = 0x20 // 0x20: Key revocation signature (key_revocation)
    case subkeyRevocation = 0x28 // 0x28: Subkey revocation signature (subkey_revocation)
    case certificationRevocation = 0x30 // 0x30: Certification revocation signature (cert_revocation)
    case timestamp = 0x40
    case thirdPartyConfirmation = 0x50
    case unknown = 0xFF
}

// MARK: - Signature Subpacket Type

public enum PGPSignatureSubpacketType: UInt8 {
    case unknown = 0 // Unknown
    case signatureCreationTime = 2
    case signatureExpirationTime = 3
    case exportableCertification = 4
    case trustSignature = 5 // TODO
    case regularExpression = 6 // TODO
    case revocable = 7 // TODO
    case keyExpirationTime = 9
    case preferredSymetricAlgorithm = 11
    case revocationKey = 12 // TODO
    case issuerKeyID = 16
    case notationData = 20 // TODO
    case preferredHashAlgorithm = 21
    case preferredCompressionAlgorithm = 22
    case keyServerPreference = 23
    case preferredKeyServer = 24
    case primaryUserID = 25
    case policyURI = 26
    case keyFlags = 27
    case signerUserID = 28
    case reasonForRevocation = 29
    case features = 30
    case signatureTarget = 31 // Seems unused at all
    case embeddedSignature = 32
    case issuerFingerprint = 33 // TODO
    case intendedRecipientFingerprint = 35 //TODO
    case attestedCertifications = 37 // TODO
    case keyBlock = 38 // TODO
}

// MARK: - Signature Flags

// 5.2.3.21.  Key Flags
public struct PGPSignatureFlags: OptionSet {
    public let rawValue: UInt8
    
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
    
    public static let unknown: PGPSignatureFlags = []
    public static let allowCertifyOtherKeys = PGPSignatureFlags(rawValue: 0x01) // indicates that this key may be used to certify other keys
    public static let allowSignData = PGPSignatureFlags(rawValue: 0x02) // indicates that this key may be used to sign data.
    public static let allowEncryptCommunications = PGPSignatureFlags(rawValue: 0x04) // indicates that this key may be used to encrypt communication.
    public static let allowEncryptStorage = PGPSignatureFlags(rawValue: 0x08) // indicates that this key may be used to encrypt storage.
    public static let secretComponentMayBeSplit = PGPSignatureFlags(rawValue: 0x10) // indicates that the secret components of this key may have been split using a secret-sharing mechanism.
    public static let allowAuthentication = PGPSignatureFlags(rawValue: 0x20) // indicates that this key may be used for authentication.
    public static let privateKeyMayBeInThePossesionOfManyPersons = PGPSignatureFlags(rawValue: 0x80) // indicates that the secret components of this key may be in the possession of more than one person.
}

// MARK: - Key Server Preference Flags

// 5.2.3.17.  Key Server Preferences
public enum PGPKeyServerPreferenceFlags: UInt8 {
    case unknown = 0x00
    case noModify = 0x80 // No-modify
}

// MARK: - Features

// 5.2.3.24.  Features
public enum PGPFeature: UInt8 {
    case modificationUnknown = 0x00
    case modificationDetection = 0x01 // Modification Detection (packets 18 and 19)
}

// MARK: - String-to-Key (S2K) Specifier Types

// 3.7.1.  String-to-Key (S2K) Specifier Types
public enum PGPS2KSpecifier: UInt8 {
    case simple = 0
    case salted = 1
    case iteratedAndSalted = 3
    // GNU extensions to the S2K algorithm.
    // see: https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;h=8ead6a8f5250656f72aea99042f392cb6749b8ff;hb=refs/heads/master#l1309
    // The "gnu-dummy S2K" is the marker which will tell that this file does *not* actually contain the secret key.
    case gnuDummy = 101
    // TODO: gnu-divert-to-card S2K
    case divertToCard = 102
}

// MARK: - S2K Usage

public enum PGPS2KUsage: UInt8 {
    case nonEncrypted = 0 // no passphrase
    case encryptedAndHashed = 254
    case encrypted = 255
}

// MARK: - Compression Algorithms

// 9.3.  Compression Algorithms
public enum PGPCompressionAlgorithm: UInt8 {
    case uncompressed = 0
    case zip = 1
    case zlib = 2
    case bzip2 = 3
}

// MARK: - Key Type

public enum PGPKeyType {
    case `public`
    case secret
}

// MARK: - Armor Type

public enum PGPArmorType: UInt {
    case message = 1
    case publicKey = 2
    case secretKey = 3
    case multipartMessagePartXOfY = 4
    case multipartMessagePartX = 5
    case signature = 6
    case cleartextSignedMessage = 7 // TODO: -----BEGIN PGP SIGNED MESSAGE-----
}

