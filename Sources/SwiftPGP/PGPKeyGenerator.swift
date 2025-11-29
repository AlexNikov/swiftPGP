//
//  PGPKeyGenerator.swift
//  SwiftPGP
//

import Foundation

/// Generates new PGP keys
public class PGPKeyGenerator {
    
    public let spec: PGPKeySpec
    
    public init(spec: PGPKeySpec = PGPKeySpec()) {
        self.spec = spec
    }
    
    public convenience init(algorithm: PGPPublicKeyAlgorithm, keyBitsLength: Int, cipherAlgorithm: PGPSymmetricAlgorithm, hashAlgorithm: PGPHashAlgorithm) {
        let spec = PGPKeySpec(keyAlgorithm: algorithm, keyBitsLength: keyBitsLength, cipherAlgorithm: cipherAlgorithm, hashAlgorithm: hashAlgorithm)
        self.init(spec: spec)
    }
    
    /// Generate a new key pair
    public func generate(for userID: String, passphrase: String?) -> PGPKey? {
        // 1. Generate key material (MPIs)
        guard let keyMaterial = PGPRSA.generateNewKeyMPIArray(bits: spec.keyBitsLength) else {
            return nil
        }
        
        let creationDate = Date()
        
        // 2. Create Public Key Packet
        let publicKeyPacket = PGPPublicKeyPacket()
        publicKeyPacket.version = 4
        publicKeyPacket.createDate = creationDate
        publicKeyPacket.publicKeyAlgorithm = spec.keyAlgorithm
        if let n = keyMaterial.n, let e = keyMaterial.e {
            publicKeyPacket.publicMPIs = [n, e]
        }
        
        // 3. Create Secret Key Packet
        let secretKeyPacket = PGPSecretKeyPacket()
        secretKeyPacket.version = 4
        secretKeyPacket.createDate = creationDate
        secretKeyPacket.publicKeyAlgorithm = spec.keyAlgorithm
        if let n = keyMaterial.n, let e = keyMaterial.e,
           let d = keyMaterial.d, let p = keyMaterial.p, let q = keyMaterial.q, let u = keyMaterial.u {
            secretKeyPacket.publicMPIs = [n, e]
            secretKeyPacket.secretMPIs = [d, p, q, u]
        }
        
        // 4. Encrypt Secret Key (S2K)
        if let passphrase = passphrase, !passphrase.isEmpty {
            // TODO: Implement S2K encryption for secret key export
            // Currently PGPSecretKeyPacket structure supports parsing encrypted keys,
            // but we need to implement the encryption logic (encrypting the secret MPIs)
            // For now, we mark it as non-encrypted or implement simple S2K
            secretKeyPacket.s2kUsage = .nonEncrypted // Placeholder
        } else {
            secretKeyPacket.s2kUsage = .nonEncrypted
        }
        
        // 5. Create User ID Packet
        let userPacket = PGPUserIDPacket(userID: userID)
        
        // 6. Create Self-Signature (Certification)
        // This confirms that the key owns the User ID
        let signaturePacket = PGPSignaturePacket()
        signaturePacket.version = 4
        signaturePacket.type = .positiveCertificationUserIDandPublicKey
        signaturePacket.publicKeyAlgorithm = spec.keyAlgorithm
        signaturePacket.hashAlgorithm = spec.hashAlgorithm
        
        // Add subpackets
        // Creation Time
        let creationTimeSubpacket = PGPSignatureSubpacket(type: .signatureCreationTime, value: creationDate as (any NSObject & NSCopying))
        signaturePacket.hashedSubpackets.append(creationTimeSubpacket)
        
        // Key Flags (Sign & Certify)
        let keyFlags: UInt8 = 0x01 | 0x02 // Certify (0x01) | Sign (0x02)
        let keyFlagsSubpacket = PGPSignatureSubpacket(type: .keyFlags, value: NSNumber(value: keyFlags))
        signaturePacket.hashedSubpackets.append(keyFlagsSubpacket)
        
        // Issuer Key ID
        let keyID = publicKeyPacket.keyID
        let issuerKeyIDSubpacket = PGPSignatureSubpacket(type: .issuerKeyID, value: keyID)
        signaturePacket.unhashedSubpackets.append(issuerKeyIDSubpacket)
        
        // Sign
        // We need to sign: Public Key Packet + User ID Packet
        // Using the secret key we just generated
        
        // TODO: Implement signing logic in PGPSignaturePacket using the raw key material
        // For now, we'll create the structure but the signature value will be empty/invalid until fully implemented
        
        // Create partial key
        guard let partialPublicKey = PGPPartialKey(packets: [publicKeyPacket, userPacket, signaturePacket]) else {
            return nil
        }
        
        guard let partialSecretKey = PGPPartialKey(packets: [secretKeyPacket, userPacket]) else {
            return nil
        }
        
        let key = PGPKey(secretKey: partialSecretKey, publicKey: partialPublicKey)
        return key
    }
}

// Compatibility alias
public typealias KeyGenerator = PGPKeyGenerator
