//
//  PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.swift
//  SwiftPGP
//

import Foundation

/// Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
public class PGPSymmetricallyEncryptedIntegrityProtectedDataPacket: PGPPacket {
    
    public private(set) var version: UInt8 = 1
    public var encryptedData: Data?
    
    public init() {
        super.init(tag: .symmetricallyEncryptedIntegrityProtectedData)
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        // Version (1 byte)
        self.version = data[offset]
        offset += 1
        
        // Encrypted data (remaining bytes)
        if offset < data.count {
            self.encryptedData = data.subdata(in: offset..<data.count)
        }
    }
    
    // MARK: - Encryption
    
    /// Encrypt data with session key
    public func encrypt(literalPacketData: Data,
                       symmetricAlgorithm: PGPSymmetricAlgorithm,
                       sessionKeyData: Data) throws {
        // Generate random IV
        let blockSize = blockSizeOfSymmetricAlgorithm(symmetricAlgorithm)
        let iv = PGPCryptoUtils.randomData(length: blockSize)
        
        // Encrypt using CFB mode with syncCFB=true (OpenPGP CFB)
        guard let encrypted = PGPCryptoCFB.encryptData(literalPacketData,
                                                       sessionKeyData: sessionKeyData,
                                                       symmetricAlgorithm: symmetricAlgorithm,
                                                       iv: iv,
                                                       syncCFB: true) else {
            throw PGPError.general
        }
        
        // Prepend version and IV
        var result = Data()
        result.append(version)
        result.append(iv)
        result.append(encrypted)
        
        self.encryptedData = result
    }
    
    // MARK: - Decryption
    
    /// Decrypt data with session key
    public func decrypt(symmetricAlgorithm: PGPSymmetricAlgorithm,
                       sessionKeyData: Data) throws -> [PGPPacket] {
        guard let encrypted = encryptedData, encrypted.count > 1 else {
            throw PGPError.invalidMessage
        }
        
        var offset = 1 // Skip version
        
        // Extract IV
        let blockSize = blockSizeOfSymmetricAlgorithm(symmetricAlgorithm)
        guard offset + blockSize <= encrypted.count else {
            throw PGPError.invalidMessage
        }
        let iv = encrypted.subdata(in: offset..<offset+blockSize)
        offset += blockSize
        
        // Encrypted data
        let encryptedData = encrypted.subdata(in: offset..<encrypted.count)
        
        // Decrypt using CFB mode with syncCFB=true
        guard let decrypted = PGPCryptoCFB.decryptData(encryptedData,
                                                      sessionKeyData: sessionKeyData,
                                                      symmetricAlgorithm: symmetricAlgorithm,
                                                      iv: iv,
                                                      syncCFB: true) else {
            throw PGPError.passphraseInvalid
        }
        
        // Parse decrypted packets
        return try PGPPacketFactory.packets(from: decrypted)
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        guard let encrypted = encryptedData else {
            throw PGPError.invalidMessage
        }
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: encrypted.count)
        var result = header
        result.append(encrypted)
        return result
    }
    
    // MARK: - Helper
    
    private func blockSizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .aes128, .aes192, .aes256: return 16
        case .cast5, .blowfish, .idea, .tripleDES: return 8
        case .twofish256: return 16
        case .plaintext: return 0
        default: return 16
        }
    }
}

