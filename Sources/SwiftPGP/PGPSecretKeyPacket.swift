//
//  PGPSecretKeyPacket.swift
//  SwiftPGP
//

import Foundation

/// Secret Key Packet - contains both public and secret key material
public class PGPSecretKeyPacket: PGPPublicKeyPacket {
    
    public var s2kUsage: PGPS2KUsage = .nonEncrypted
    public var s2k: PGPS2K?
    public var symmetricAlgorithm: PGPSymmetricAlgorithm = .plaintext
    public var ivData: Data?
    
    // Encrypted part (before decryption)
    private var encryptedMPIPartData: Data?
    
    // Decrypted secret MPIs (after decryption)
    public var secretMPIs: [PGPMPI] = []
    
    private var wasDecrypted: Bool = false
    
    public var isEncryptedWithPassphrase: Bool {
        if wasDecrypted {
            return false
        }
        return s2kUsage == .encrypted || s2kUsage == .encryptedAndHashed
    }
    
    public override init(tag: PGPPacketTag) {
        super.init(tag: tag)
    }
    
    public override init() {
        super.init(tag: .secretKey)
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        // First parse public key part (inherited from PGPPublicKeyPacket)
        try super.parse(data: data)
        
        // Now parse secret key part
        // After public key MPIs, we have:
        // - S2K Usage (1 byte)
        // - If encrypted: Symmetric Algorithm (1 byte), S2K, IV, encrypted MPIs
        // - If not encrypted: MPIs + checksum
        
        var offset = calculatePublicKeyPartLength()
        
        guard offset < data.count else {
            throw PGPError.invalidMessage
        }
        
        s2kUsage = PGPS2KUsage(rawValue: data[offset]) ?? .nonEncrypted
        offset += 1
        
        if s2kUsage == .encrypted || s2kUsage == .encryptedAndHashed {
            // Encrypted part
            try parseEncryptedPart(data: data, offset: &offset)
        } else {
            // Unencrypted part
            try parseUnencryptedPart(data: data, offset: &offset)
        }
    }
    
    private func calculatePublicKeyPartLength() -> Int {
        // Version (1) + Timestamp (4) + Algorithm (1) + MPIs
        var length = 6
        for mpi in publicMPIs {
            length += mpi.packetLength
        }
        return length
    }
    
    private func parseEncryptedPart(data: Data, offset: inout Int) throws {
        guard offset < data.count else {
            throw PGPError.invalidMessage
        }
        
        // Symmetric algorithm
        symmetricAlgorithm = PGPSymmetricAlgorithm(rawValue: data[offset]) ?? .plaintext
        offset += 1
        
        // S2K
        guard let (s2k, s2kLength) = PGPS2K.s2k(from: data, at: offset) else {
            throw PGPError.invalidMessage
        }
        self.s2k = s2k
        offset += s2kLength
        
        // IV (Initial Vector) - block size of symmetric algorithm
        let blockSize = blockSizeOfSymmetricAlgorithm(symmetricAlgorithm)
        if blockSize > 0 && blockSize <= 16 {
            guard offset + blockSize <= data.count else {
                throw PGPError.invalidMessage
            }
            ivData = data.subdata(in: offset..<offset + blockSize)
            offset += blockSize
        }
        
        // Encrypted MPIs
        encryptedMPIPartData = data.subdata(in: offset..<data.count)
    }
    
    private func parseUnencryptedPart(data: Data, offset: inout Int) throws {
        // Parse secret MPIs directly
        var currentOffset = offset
        
        // Parse MPIs based on algorithm (same as public key)
        switch publicKeyAlgorithm {
        case .rsa, .rsaEncryptOnly, .rsaSignOnly:
            // RSA: d (private exponent), p, q, u
            if let mpiD = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.d, at: currentOffset) {
                currentOffset += mpiD.packetLength
                secretMPIs.append(mpiD)
            }
            if let mpiP = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.p, at: currentOffset) {
                currentOffset += mpiP.packetLength
                secretMPIs.append(mpiP)
            }
            if let mpiQ = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.q, at: currentOffset) {
                currentOffset += mpiQ.packetLength
                secretMPIs.append(mpiQ)
            }
            if let mpiU = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.u, at: currentOffset) {
                currentOffset += mpiU.packetLength
                secretMPIs.append(mpiU)
            }
            
        case .dsa:
            // DSA: x (secret key)
            if let mpiX = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.x, at: currentOffset) {
                currentOffset += mpiX.packetLength
                secretMPIs.append(mpiX)
            }
            
        default:
            // Other algorithms - store raw data for now
            break
        }
        
        // Checksum (2 bytes) or SHA1 hash (20 bytes)
        if s2kUsage == .encryptedAndHashed {
            // SHA1 hash (20 bytes) - should be verified after decryption
            // Skip for now, will verify in decryptedWithPassphrase
        } else {
            // Simple checksum (2 bytes)
            guard currentOffset + 2 <= data.count else {
                throw PGPError.invalidMessage
            }
            // Verify checksum
            let checksumData = data.subdata(in: offset..<currentOffset)
            let calculatedChecksum = checksumData.pgpChecksum
            let storedChecksum = data.subdata(in: currentOffset..<currentOffset+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
            
            if calculatedChecksum != storedChecksum {
                throw PGPError.passphraseInvalid
            }
        }
        
        offset = currentOffset
    }
    
    private func blockSizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .aes128, .aes192, .aes256: return 16
        case .cast5, .blowfish, .idea, .tripleDES: return 8
        case .twofish256: return 16
        case .plaintext: return 0
        default: return 16
        }
    }
    
    // MARK: - Decryption
    
    /// Decrypt secret key with passphrase
    public func decryptedWithPassphrase(_ passphrase: String) throws -> PGPSecretKeyPacket {
        guard isEncryptedWithPassphrase else {
            return self
        }
        
        guard let s2k = s2k, let ivData = ivData, let encryptedData = encryptedMPIPartData else {
            throw PGPError.general
        }
        
        // Generate session key from passphrase
        guard let sessionKey = s2k.produceSessionKey(passphrase: passphrase, symmetricAlgorithm: symmetricAlgorithm) else {
            throw PGPError.passphraseInvalid
        }
        
        // Decrypt encrypted MPIs (simplified - full implementation would use CFB mode)
        // TODO: Implement proper CFB decryption
        let decryptedData = try decryptCFB(data: encryptedData, key: sessionKey, iv: ivData, algorithm: symmetricAlgorithm)
        
        // Parse decrypted MPIs
        let decryptedPacket = PGPSecretKeyPacket()
        decryptedPacket.version = self.version
        decryptedPacket.createDate = self.createDate
        decryptedPacket.publicKeyAlgorithm = self.publicKeyAlgorithm
        decryptedPacket.publicMPIs = self.publicMPIs
        decryptedPacket.s2kUsage = self.s2kUsage
        decryptedPacket.symmetricAlgorithm = self.symmetricAlgorithm
        
        var offset = 0
        try decryptedPacket.parseUnencryptedPart(data: decryptedData, offset: &offset)
        
        // Verify hash if encrypted and hashed
        if s2kUsage == .encryptedAndHashed {
            guard decryptedData.count >= 20 else {
                throw PGPError.passphraseInvalid
            }
            let clearTextData = decryptedData.prefix(decryptedData.count - 20)
            let storedHash = decryptedData.suffix(20)
            let calculatedHash = clearTextData.pgpSHA1
            
            if storedHash != calculatedHash {
                throw PGPError.passphraseInvalid
            }
        }
        
        decryptedPacket.wasDecrypted = true
        return decryptedPacket
    }
    
    /// CFB decryption using PGPCryptoCFB
    private func decryptCFB(data: Data, key: Data, iv: Data, algorithm: PGPSymmetricAlgorithm) throws -> Data {
        // Use syncCFB=false for secret keys (standard CFB)
        guard let decrypted = PGPCryptoCFB.decryptData(data,
                                                       sessionKeyData: key,
                                                       symmetricAlgorithm: algorithm,
                                                       iv: iv,
                                                       syncCFB: false) else {
            throw PGPError.passphraseInvalid
        }
        return decrypted
    }
    
    /// Get secret MPI by identifier
    public func secretMPI(identifier: String) -> PGPMPI? {
        return secretMPIs.first { $0.identifier == identifier }
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        var body = try super.export()
        
        // Remove header from super.export() to get just body
        // Find where body starts (after header)
        // For simplicity, rebuild the whole packet
        
        var keyBody = buildKeyBodyData(forceV4: false)
        
        // Add S2K usage
        keyBody.append(s2kUsage.rawValue)
        
        if isEncryptedWithPassphrase {
            // Encrypted format
            keyBody.append(symmetricAlgorithm.rawValue)
            if let s2k = s2k {
                keyBody.append(try s2k.export())
            }
            if let iv = ivData {
                keyBody.append(iv)
            }
            if let encrypted = encryptedMPIPartData {
                keyBody.append(encrypted)
            }
        } else {
            // Unencrypted format - export secret MPIs
            for mpi in secretMPIs {
                keyBody.append(mpi.exportMPI())
            }
            
            // Add checksum
            let checksum = keyBody.pgpChecksum
            var checksumBE = checksum.bigEndian
            keyBody.append(Data(bytes: &checksumBE, count: 2))
        }
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: keyBody.count)
        var result = header
        result.append(keyBody)
        return result
    }
}

