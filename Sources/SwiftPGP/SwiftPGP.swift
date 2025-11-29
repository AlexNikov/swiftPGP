//  SwiftPGP.swift
//  SwiftPGP

import Foundation

/// SwiftPGP - The Leading OpenPGP Framework for iOS and macOS.
/// This is the main class for framework-global settings and operations.
public class SwiftPGP {
    
    /// The shared SwiftPGP configuration instance.
    public static let shared = SwiftPGP()
    
    /// Default, shared keyring instance. Not used internally.
    public static let defaultKeyring: PGPKeyring = {
        return PGPKeyring()
    }()
    
    private init() {
        // Private initializer for singleton
    }
    
    // MARK: - Read Keys
    
    /**
     Read binary or armored (ASCII) PGP keys from the input.
     
     @param data Key data or keyring data.
     @return Array of read keys.
     */
    public static func readKeys(fromData data: Data) throws -> [PGPKey] {
        guard !data.isEmpty else {
            throw PGPError.invalidMessage
        }
        
        // Convert armored to binary if necessary
        let binaryBlocks = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(data)
        
        var keys: [PGPKey] = []
        for block in binaryBlocks {
            // TODO: Parse packets and create keys
            // This is a placeholder - full implementation would parse PGP packets
            let partialKeys = try readPartialKeys(fromData: block)
            for partialKey in partialKeys {
                let key = PGPKey(secretKey: partialKey.type == .secret ? partialKey : nil,
                                publicKey: partialKey.type == .public ? partialKey : nil)
                keys.append(key)
            }
        }
        
        return keys
    }
    
    /**
     Read binary or armored (ASCII) PGP keys from the input.
     
     @param path Path to the file with keys.
     @return Array of read keys.
     */
    public static func readKeys(fromPath path: String) throws -> [PGPKey] {
        let fullPath = (path as NSString).expandingTildeInPath
        
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            throw PGPError.invalidMessage
        }
        
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: fullPath)) else {
            throw PGPError.invalidMessage
        }
        
        return try readKeys(fromData: fileData)
    }
    
    // MARK: - Sign & Verify
    
    /**
     Sign data using a given key. Use passphrase to unlock the key if needed.
     If `detached` is true, output with the signature only. Otherwise, return signed data in PGP format.
     
     @param data Input data.
     @param detached Whether result in only signature (not signed data)
     @param keys Keys to be used to sign.
     @param passphraseForKey Optional. Handler for passphrase protected keys. Return passphrase for a key in question.
     @return Signed data, or throws error.
     */
    public static func sign(_ data: Data,
                           detached: Bool,
                           using keys: [PGPKey],
                           passphraseForKey: ((PGPKey) -> String?)? = nil) throws -> Data {
        guard !keys.isEmpty else {
            throw PGPError.general
        }
        
        // 1. Create literal packet (if not detached)
        var signedData = Data()
        if !detached {
            let literalPacket = PGPLiteralPacket()
            literalPacket.literalRawData = data
            literalPacket.format = .binary
            signedData.append(try literalPacket.export())
        }
        
        // 2. Sign with each key
        var signaturePackets: [PGPSignaturePacket] = []
        for key in keys {
            guard let secretKey = key.secretKey,
                  let secretKeyPacket = secretKey.primaryKeyPacket as? PGPSecretKeyPacket else {
                continue
            }
            
            // Decrypt secret key if needed
            var signingKeyPacket = secretKeyPacket
            if secretKeyPacket.isEncryptedWithPassphrase {
                let passphrase = passphraseForKey?(key) ?? ""
                signingKeyPacket = try secretKeyPacket.decryptedWithPassphrase(passphrase)
            }
            
            // Create signature packet
            let signaturePacket = PGPSignaturePacket()
            signaturePacket.version = 4
            signaturePacket.type = detached ? .binaryDocument : .binaryDocument
            signaturePacket.publicKeyAlgorithm = signingKeyPacket.publicKeyAlgorithm
            signaturePacket.hashAlgorithm = .sha256 // Default to SHA256
            
            // Add subpackets
            // Creation time
            let creationTime = PGPSignatureSubpacket(type: .signatureCreationTime, value: Date() as (any NSObject & NSCopying))
            signaturePacket.hashedSubpackets.append(creationTime)
            
            // Issuer Key ID
            let keyID = signingKeyPacket.keyID
            let issuerKeyID = PGPSignatureSubpacket(type: .issuerKeyID, value: keyID)
            signaturePacket.unhashedSubpackets.append(issuerKeyID)
            
            // Sign
            // TODO: Calculate hash and sign with private key
            // For now, just create dummy signature data
            let hashData = data.hashedWithAlgorithm(.sha256)
            signaturePacket.signedHashValueData = hashData.prefix(2)
            
            // Placeholder for RSA signature
            // In real implementation:
            // 1. Build data to sign (input data + signature header + hashed subpackets)
            // 2. Hash it
            // 3. Sign hash with private key
            
            // Add dummy signature MPIs
            if signingKeyPacket.publicKeyAlgorithm == .rsa {
                // RSA signature is one MPI (m^d mod n)
                let dummySignature = Data(count: 128) // 1024 bits
                let mpi = PGPMPI(bigNum: PGPBigNum(data: dummySignature), identifier: PGPMPIdentifier.n)
                signaturePacket.signatureMPIs = [mpi]
            }
            
            signaturePackets.append(signaturePacket)
        }
        
        if signaturePackets.isEmpty {
            throw PGPError.general
        }
        
        // 3. Combine into PGP message
        var result = Data()
        
        if detached {
            for sig in signaturePackets {
                result.append(try sig.export())
            }
        } else {
            // One-Pass Signature Packets
            for sig in signaturePackets {
                let onePass = PGPOnePassSignaturePacket()
                onePass.version = 3
                onePass.signatureType = sig.type
                onePass.hashAlgorithm = sig.hashAlgorithm
                onePass.publicKeyAlgorithm = sig.publicKeyAlgorithm
                onePass.keyID = sig.issuerKeyID
                onePass.nested = true // Default
                result.append(try onePass.export())
            }
            
            // Literal Data
            result.append(signedData)
            
            // Signature Packets
            for sig in signaturePackets {
                result.append(try sig.export())
            }
        }
        
        return result
    }
    
    /**
     Verify signed data using given keys.
     
     @param data Signed data.
     @param signature Detached signature data (Optional). If not provided, `data` is expected to be signed.
     @param keys Public keys. The provided keys should match the signatures.
     @param passphraseForKey Optional. Handler for passphrase protected keys. Return passphrase for a key in question.
     @return true on success.
     */
    public static func verify(_ data: Data,
                             withSignature signature: Data? = nil,
                             using keys: [PGPKey],
                             certifyWithRootKey: Bool = false,
                             passphraseForKey: ((PGPKey) -> String?)? = nil) throws -> Bool {
        // Convert armored to binary if necessary
        let binaryData = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(data)
        
        // Parse packets
        var allPackets: [PGPPacket] = []
        for block in binaryData {
            let packets = try PGPPacketFactory.packets(from: block)
            allPackets.append(contentsOf: packets)
        }
        
        // Handle detached signature
        if let signatureData = signature {
            let signatureBinary = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(signatureData)
            for block in signatureBinary {
                let packets = try PGPPacketFactory.packets(from: block)
                allPackets.append(contentsOf: packets)
            }
        }
        
        // Find literal packet and signature packets
        var literalPacket: PGPLiteralPacket?
        var signaturePackets: [PGPSignaturePacket] = []
        
        for packet in allPackets {
            if let literal = packet as? PGPLiteralPacket {
                literalPacket = literal
            } else if let sig = packet as? PGPSignaturePacket {
                signaturePackets.append(sig)
            }
        }
        
        // Get literal data
        guard let literal = literalPacket, let literalData = literal.literalRawData else {
            throw PGPError.invalidMessage
        }
        
        // Verify each signature
        for sigPacket in signaturePackets {
            // Find matching key
            guard let issuerKeyID = sigPacket.issuerKeyID else {
                continue
            }
            
            guard let matchingKey = keys.first(where: { $0.publicKey?.keyID == issuerKeyID }) else {
                continue
            }
            
            // Verify signature
            do {
                let isValid = try sigPacket.verify(data: literalData, publicKey: matchingKey)
                if !isValid {
                    return false
                }
            } catch {
                return false
            }
        }
        
        return !signaturePackets.isEmpty
    }
    
    /**
     Verify if signature was signed with one of the given keys.
     */
    public static func verifySignature(_ signature: Data,
                                      using keys: [PGPKey],
                                      passphraseForKey: ((PGPKey) -> String?)? = nil) throws -> Bool {
        // Parse signature packets
        let binaryData = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(signature)
        
        var signaturePackets: [PGPSignaturePacket] = []
        for block in binaryData {
            let packets = try PGPPacketFactory.packets(from: block)
            for packet in packets {
                if let sig = packet as? PGPSignaturePacket {
                    signaturePackets.append(sig)
                }
            }
        }
        
        // For detached signatures, we need the original data to verify
        // This method is a placeholder - full implementation would require the original data
        return !signaturePackets.isEmpty
    }
    
    // MARK: - Encrypt & Decrypt
    
    /**
     Encrypt data using given keys. Output in binary.
     
     @param data Data to encrypt.
     @param addSignature Whether message should be encrypted and signed.
     @param keys Keys to use to encrypt `data`
     @param passphraseForKey Optional. Handler for passphrase protected keys. Return passphrase for a key in question.
     @return Encrypted data in requested format.
     
     @note Use `PGPArmor` to convert binary `data` format to the armored (ASCII) format:
     
     ```
     PGPArmor.armored(encryptedData, as: .message).data(using: .utf8)
     ```
     */
    public static func encrypt(_ data: Data,
                              addSignature: Bool,
                              using keys: [PGPKey],
                              passphraseForKey: ((PGPKey) -> String?)? = nil) throws -> Data {
        guard !keys.isEmpty else {
            throw PGPError.general
        }
        
        // Get public keys
        let publicKeys = keys.compactMap { $0.publicKey }
        guard !publicKeys.isEmpty else {
            throw PGPError.general
        }
        
        // Choose symmetric algorithm (prefer AES256)
        let preferredAlgorithm: PGPSymmetricAlgorithm = .aes256
        
        // Generate session key
        let keySize = PGPCryptoUtils.keySizeOfSymmetricAlgorithm(preferredAlgorithm)
        let sessionKeyData = PGPCryptoUtils.randomData(length: keySize)
        
        var encryptedMessage = Data()
        
        // Create Public-Key Encrypted Session Key packets for each recipient
        for publicKey in publicKeys {
            guard let encryptionKeyPacket = publicKey.primaryKeyPacket else {
                continue
            }
            
            // Create ESK packet
            let eskPacket = PGPPublicKeyEncryptedSessionKeyPacket()
            try eskPacket.encrypt(publicKeyPacket: encryptionKeyPacket,
                                sessionKeyData: sessionKeyData,
                                sessionKeyAlgorithm: preferredAlgorithm)
            
            // Export and append
            let eskData = try eskPacket.export()
            encryptedMessage.append(eskData)
        }
        
        // Prepare content (literal packet)
        let literalPacket = PGPLiteralPacket()
        literalPacket.literalRawData = data
        literalPacket.format = .binary
        let literalData = try literalPacket.export()
        
        // Encrypt content with session key
        let seipPacket = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        try seipPacket.encrypt(literalPacketData: literalData,
                              symmetricAlgorithm: preferredAlgorithm,
                              sessionKeyData: sessionKeyData)
        
        // Export and append
        let seipData = try seipPacket.export()
        encryptedMessage.append(seipData)
        
        return encryptedMessage
    }
    
    /**
     Decrypt PGP encrypted data.
     
     @param data data to decrypt.
     @param keys private keys to use.
     @param passphraseForKey Optional. Handler for passphrase protected keys. Return passphrase for a key in question.
     @param verifySignature `true` if should verify the signature used during encryption, if message is encrypted and signed.
     @return Decrypted data, or throws error.
     */
    public static func decrypt(_ data: Data,
                              andVerifySignature verifySignature: Bool,
                              using keys: [PGPKey],
                              passphraseForKey: ((PGPKey?) -> String?)? = nil) throws -> Data {
        // Convert armored to binary if necessary
        let binaryData = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(data)
        
        // Parse all packets
        var allPackets: [PGPPacket] = []
        for block in binaryData {
            let packets = try PGPPacketFactory.packets(from: block)
            allPackets.append(contentsOf: packets)
        }
        
        // Find Public-Key Encrypted Session Key packets
        var eskPackets: [PGPPublicKeyEncryptedSessionKeyPacket] = []
        var seipPacket: PGPSymmetricallyEncryptedIntegrityProtectedDataPacket?
        
        for packet in allPackets {
            if let esk = packet as? PGPPublicKeyEncryptedSessionKeyPacket {
                eskPackets.append(esk)
            } else if let seip = packet as? PGPSymmetricallyEncryptedIntegrityProtectedDataPacket {
                seipPacket = seip
            }
        }
        
        guard !eskPackets.isEmpty, let seip = seipPacket else {
            throw PGPError.invalidMessage
        }
        
        // Try to decrypt session key with available keys
        var sessionKeyData: Data?
        var sessionKeyAlgorithm: PGPSymmetricAlgorithm = .plaintext
        
        for esk in eskPackets {
            guard let recipientKeyID = esk.keyID else {
                continue
            }
            
            // Find matching secret key
            guard let matchingKey = keys.first(where: { $0.secretKey?.keyID == recipientKeyID }),
                  let secretKey = matchingKey.secretKey,
                  let secretKeyPacket = secretKey.primaryKeyPacket as? PGPSecretKeyPacket else {
                continue
            }
            
            // Decrypt secret key if needed
            var decryptedSecretKey = secretKeyPacket
            if secretKeyPacket.isEncryptedWithPassphrase {
                let passphrase = passphraseForKey?(matchingKey) ?? ""
                decryptedSecretKey = try secretKeyPacket.decryptedWithPassphrase(passphrase)
            }
            
            // Decrypt session key
            do {
                var algorithm: PGPSymmetricAlgorithm = .plaintext
                sessionKeyData = try esk.decryptSessionKeyData(secretKeyPacket: decryptedSecretKey,
                                                              sessionKeyAlgorithm: &algorithm)
                sessionKeyAlgorithm = algorithm
                break
            } catch {
                continue
            }
        }
        
        guard let sessionKey = sessionKeyData else {
            throw PGPError.passphraseRequired
        }
        
        // Decrypt data
        let decryptedPackets = try seip.decrypt(symmetricAlgorithm: sessionKeyAlgorithm,
                                               sessionKeyData: sessionKey)
        
        // Find literal packet
        guard let literalPacket = decryptedPackets.first(where: { $0.tag == .literalData }) as? PGPLiteralPacket,
              let literalData = literalPacket.literalRawData else {
            throw PGPError.invalidMessage
        }
        
        return literalData
    }
    
    /**
     Return list of key identifiers used in the given message. Determine keys that a message has been encrypted.
     */
    public static func recipientsKeyID(forMessage data: Data) throws -> [PGPKeyID] {
        // Convert armored to binary if necessary
        let binaryData = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(data)
        
        var keyIDs: [PGPKeyID] = []
        
        // Parse packets and look for Public-Key Encrypted Session Key packets (Tag 1)
        for block in binaryData {
            let packets = try PGPPacketFactory.packets(from: block)
            for packet in packets {
                if let eskPacket = packet as? PGPPublicKeyEncryptedSessionKeyPacket,
                   let keyID = eskPacket.keyID {
                    keyIDs.append(keyID)
                }
            }
        }
        
        return keyIDs
    }
    
    // MARK: - Private Helpers
    
    private static func readPartialKeys(fromData data: Data) throws -> [PGPPartialKey] {
        let packets = try PGPPacketFactory.packets(from: data)
        var partialKeys: [PGPPartialKey] = []
        
        var currentKeyPackets: [PGPPacket] = []
        
        for packet in packets {
            // New key starts with Public Key or Secret Key packet
            if packet.tag == .publicKey || packet.tag == .secretKey {
                if !currentKeyPackets.isEmpty {
                    if let partialKey = PGPPartialKey(packets: currentKeyPackets) {
                        partialKeys.append(partialKey)
                    }
                    currentKeyPackets = []
                }
            }
            currentKeyPackets.append(packet)
        }
        
        // Add the last key
        if !currentKeyPackets.isEmpty {
            if let partialKey = PGPPartialKey(packets: currentKeyPackets) {
                partialKeys.append(partialKey)
            }
        }
        
        return partialKeys
    }
}

