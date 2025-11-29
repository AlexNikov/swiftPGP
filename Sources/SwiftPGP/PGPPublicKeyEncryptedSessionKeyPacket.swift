//
//  PGPPublicKeyEncryptedSessionKeyPacket.swift
//  SwiftPGP
//

import Foundation

/// Public-Key Encrypted Session Key Packet (Tag 1)
public class PGPPublicKeyEncryptedSessionKeyPacket: PGPPacket {
    
    public var version: UInt8 = 3
    public var keyID: PGPKeyID?
    public var publicKeyAlgorithm: PGPPublicKeyAlgorithm = .rsa
    public var encryptedMPIs: [PGPMPI] = []
    
    public init() {
        super.init(tag: .publicKeyEncryptedSessionKey)
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        // Version
        self.version = data[offset]
        offset += 1
        
        // Key ID (8 bytes)
        guard offset + 8 <= data.count else { throw PGPError.invalidMessage }
        let keyIDData = data.subdata(in: offset..<offset+8)
        self.keyID = PGPKeyID(longKey: keyIDData)
        offset += 8
        
        // Public key algorithm
        guard offset < data.count else { throw PGPError.invalidMessage }
        self.publicKeyAlgorithm = PGPPublicKeyAlgorithm(rawValue: data[offset]) ?? .private1
        offset += 1
        
        // Encrypted session key MPIs (algorithm-specific)
        let remainingData = data.subdata(in: offset..<data.count)
        try parseEncryptedMPIs(from: remainingData)
    }
    
    private func parseEncryptedMPIs(from data: Data) throws {
        var offset = 0
        encryptedMPIs = []
        
        switch publicKeyAlgorithm {
        case .rsa, .rsaEncryptOnly, .rsaSignOnly:
            // RSA: one MPI (encrypted session key)
            guard let mpi = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.m, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpi.packetLength
            encryptedMPIs.append(mpi)
            
        case .elgamal, .elgamalEncryptorSign:
            // Elgamal: two MPIs
            guard let mpi1 = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.g, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpi1.packetLength
            encryptedMPIs.append(mpi1)
            
            guard let mpi2 = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.m, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpi2.packetLength
            encryptedMPIs.append(mpi2)
            
        default:
            // Other algorithms - store raw data
            break
        }
    }
    
    // MARK: - Encryption
    
    /// Encrypt session key with public key
    public func encrypt(publicKeyPacket: PGPPublicKeyPacket,
                       sessionKeyData: Data,
                       sessionKeyAlgorithm: PGPSymmetricAlgorithm) throws {
        self.keyID = publicKeyPacket.keyID
        self.publicKeyAlgorithm = publicKeyPacket.publicKeyAlgorithm
        
        // Build data to encrypt: algorithm (1 byte) + session key + checksum (2 bytes)
        var dataToEncrypt = Data()
        dataToEncrypt.append(sessionKeyAlgorithm.rawValue)
        dataToEncrypt.append(sessionKeyData)
        
        let checksum = sessionKeyData.pgpChecksum
        var checksumBytes = checksum.bigEndian
        dataToEncrypt.append(Data(bytes: &checksumBytes, count: 2))
        
        // Encrypt with public key
        switch publicKeyAlgorithm {
        case .rsa, .rsaEncryptOnly, .rsaSignOnly:
            guard let encryptedData = PGPRSA.publicEncrypt(dataToEncrypt, withPublicKeyPacket: publicKeyPacket) else {
                throw PGPError.general
            }
            let mpi = PGPMPI(bigNum: PGPBigNum(data: encryptedData), identifier: PGPMPIdentifier.m)
            encryptedMPIs = [mpi]
            
        default:
            throw PGPError.general
        }
    }
    
    // MARK: - Decryption
    
    /// Decrypt session key with secret key
    public func decryptSessionKeyData(secretKeyPacket: PGPSecretKeyPacket,
                                      sessionKeyAlgorithm: inout PGPSymmetricAlgorithm) throws -> Data {
        guard let encryptedMPI = encryptedMPIs.first else {
            throw PGPError.invalidMessage
        }
        
        let encryptedData = encryptedMPI.bodyData()
        
        // Decrypt with secret key
        guard let decryptedData = PGPRSA.privateDecrypt(encryptedData, withSecretKeyPacket: secretKeyPacket) else {
            throw PGPError.passphraseInvalid
        }
        
        // Parse decrypted data: algorithm (1 byte) + session key + checksum (2 bytes)
        guard decryptedData.count >= 3 else {
            throw PGPError.invalidMessage
        }
        
        sessionKeyAlgorithm = PGPSymmetricAlgorithm(rawValue: decryptedData[0]) ?? .plaintext
        let sessionKeyData = decryptedData.subdata(in: 1..<decryptedData.count-2)
        let checksumData = decryptedData.subdata(in: decryptedData.count-2..<decryptedData.count)
        let expectedChecksum = checksumData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        let actualChecksum = sessionKeyData.pgpChecksum
        
        guard expectedChecksum == actualChecksum else {
            throw PGPError.invalidMessage
        }
        
        return sessionKeyData
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        var body = Data()
        body.append(version)
        
        // Key ID
        if let keyID = keyID, let keyIDData = Data(hexString: keyID.longIdentifier) {
            body.append(keyIDData.prefix(8))
        } else {
            body.append(Data(repeating: 0, count: 8))
        }
        
        body.append(publicKeyAlgorithm.rawValue)
        
        // Encrypted MPIs
        for mpi in encryptedMPIs {
            body.append(mpi.exportMPI())
        }
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: body.count)
        var result = header
        result.append(body)
        return result
    }
}

