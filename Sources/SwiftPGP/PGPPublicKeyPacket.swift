//
//  PGPPublicKeyPacket.swift
//  SwiftPGP
//

import Foundation

public class PGPPublicKeyPacket: PGPPacket {
    
    public var version: UInt8 = 4
    public var createDate: Date = Date()
    public var publicKeyAlgorithm: PGPPublicKeyAlgorithm = .rsa
    
    // MPIs (Multiprecision Integers) for key material
    public var publicMPIs: [PGPMPI] = []
    
    // Legacy: keep keyData for backward compatibility, but prefer publicMPIs
    public var keyData: Data {
        get {
            // Export MPIs to data
            var data = Data()
            for mpi in publicMPIs {
                data.append(mpi.exportMPI())
            }
            return data
        }
        set {
            // Try to parse MPIs from data
            try? parseMPIs(from: newValue)
        }
    }
    
    public init() {
        super.init(tag: .publicKey)
    }
    
    public override init(tag: PGPPacketTag) {
        super.init(tag: tag)
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        self.version = data[offset]
        offset += 1
        
        guard version >= 3 && version <= 4 else {
            throw PGPError.invalidMessage
        }
        
        guard offset + 4 <= data.count else { throw PGPError.invalidMessage }
        let timestamp = data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        self.createDate = Date(timeIntervalSince1970: TimeInterval(timestamp))
        offset += 4
        
        // V3 keys have validity period (deprecated)
        if version == 3 {
            guard offset + 2 <= data.count else { throw PGPError.invalidMessage }
            // Skip validity period
            offset += 2
        }
        
        guard offset < data.count else { throw PGPError.invalidMessage }
        self.publicKeyAlgorithm = PGPPublicKeyAlgorithm(rawValue: data[offset]) ?? .private1
        offset += 1
        
        // Parse MPIs based on algorithm
        let mpiData = data.subdata(in: offset..<data.count)
        try parseMPIs(from: mpiData)
    }
    
    private func parseMPIs(from data: Data) throws {
        var offset = 0
        publicMPIs = []
        
        switch publicKeyAlgorithm {
        case .rsa, .rsaEncryptOnly, .rsaSignOnly:
            // RSA: n (modulus) and e (exponent)
            guard let mpiN = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.n, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiN.packetLength
            publicMPIs.append(mpiN)
            
            guard let mpiE = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.e, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiE.packetLength
            publicMPIs.append(mpiE)
            
        case .dsa:
            // DSA: p, q, g, y
            guard let mpiP = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.p, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiP.packetLength
            publicMPIs.append(mpiP)
            
            guard let mpiQ = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.q, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiQ.packetLength
            publicMPIs.append(mpiQ)
            
            guard let mpiG = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.g, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiG.packetLength
            publicMPIs.append(mpiG)
            
            guard let mpiY = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.y, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiY.packetLength
            publicMPIs.append(mpiY)
            
        case .elgamal, .elgamalEncryptorSign:
            // Elgamal: p, g, y
            guard let mpiP = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.p, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiP.packetLength
            publicMPIs.append(mpiP)
            
            guard let mpiG = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.g, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiG.packetLength
            publicMPIs.append(mpiG)
            
            guard let mpiY = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.y, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiY.packetLength
            publicMPIs.append(mpiY)
            
        default:
            // Unsupported algorithm - store raw data
            break
        }
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        var body = Data()
        
        body.append(version)
        
        var timestamp = UInt32(createDate.timeIntervalSince1970).bigEndian
        let timeData = Data(bytes: &timestamp, count: 4)
        body.append(timeData)
        
        if version == 3 {
            // V3 validity period (0 = no expiration)
            var validity: UInt16 = 0
            let validityData = Data(bytes: &validity, count: 2)
            body.append(validityData)
        }
        
        body.append(publicKeyAlgorithm.rawValue)
        
        // Export MPIs
        for mpi in publicMPIs {
            body.append(mpi.exportMPI())
        }
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: body.count)
        return header + body
    }
    
    // MARK: - Helper Methods
    
    /// Get MPI by identifier
    public func mpi(identifier: String) -> PGPMPI? {
        return publicMPIs.first { $0.identifier == identifier }
    }
    
    // MARK: - Fingerprint & KeyID
    
    /// Build key body data (version + timestamp + algorithm + MPIs)
    internal func buildKeyBodyData(forceV4: Bool = false) -> Data {
        var data = Data()
        data.append(version)
        
        var timestamp = UInt32(createDate.timeIntervalSince1970).bigEndian
        let timeData = Data(bytes: &timestamp, count: 4)
        data.append(timeData)
        
        if !forceV4 && version == 3 {
            // V3 validity period (deprecated)
            var validity: UInt16 = 0
            let validityData = Data(bytes: &validity, count: 2)
            data.append(validityData)
        }
        
        data.append(publicKeyAlgorithm.rawValue)
        
        // Export MPIs
        for mpi in publicMPIs {
            data.append(mpi.exportMPI())
        }
        
        return data
    }
    
    /// Export key packet in old-style format (used for fingerprint calculation)
    /// Old-style: 0x99 (tag) + 2-byte length + body
    public func exportKeyPacketOldStyle() -> Data {
        let keyBody = buildKeyBodyData(forceV4: false)
        
        var data = Data()
        // Old format header: 0x99 (Public Key tag in old format) + 2-byte length
        data.append(0x99)
        let length = UInt16(keyBody.count)
        var lengthBE = length.bigEndian
        data.append(Data(bytes: &lengthBE, count: 2))
        data.append(keyBody)
        
        return data
    }
    
    /// Calculate fingerprint (SHA1 of old-style packet)
    public var fingerprint: PGPFingerprint {
        let keyPacketData = exportKeyPacketOldStyle()
        return PGPFingerprint(keyData: keyPacketData)
    }
    
    /// Calculate Key ID from fingerprint
    public var keyID: PGPKeyID {
        return PGPKeyID(fingerprint: fingerprint)
    }
}
