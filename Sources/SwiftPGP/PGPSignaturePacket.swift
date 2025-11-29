//
//  PGPSignaturePacket.swift
//  SwiftPGP
//

import Foundation

/// Signature Packet (Tag 2)
public class PGPSignaturePacket: PGPPacket {
    
    public var version: UInt8 = 4
    public var type: PGPSignatureType = .unknown
    public var publicKeyAlgorithm: PGPPublicKeyAlgorithm = .rsa
    public var hashAlgorithm: PGPHashAlgorithm = .sha1
    public var hashedSubpackets: [PGPSignatureSubpacket] = []
    public var unhashedSubpackets: [PGPSignatureSubpacket] = []
    public var signedHashValueData: Data?
    public var signatureMPIs: [PGPMPI] = []
    
    public init() {
        super.init(tag: .signature)
    }
    
    /// Create signature packet for signing
    public static func signaturePacket(type: PGPSignatureType, hashAlgorithm: PGPHashAlgorithm) -> PGPSignaturePacket {
        let packet = PGPSignaturePacket()
        packet.type = type
        packet.hashAlgorithm = hashAlgorithm
        return packet
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        // Version
        self.version = data[offset]
        offset += 1
        
        guard version == 4 else {
            // Only V4 supported for now
            throw PGPError.invalidMessage
        }
        
        // Signature type
        guard offset < data.count else { throw PGPError.invalidMessage }
        self.type = PGPSignatureType(rawValue: data[offset]) ?? .unknown
        offset += 1
        
        // Public key algorithm
        guard offset < data.count else { throw PGPError.invalidMessage }
        self.publicKeyAlgorithm = PGPPublicKeyAlgorithm(rawValue: data[offset]) ?? .private1
        offset += 1
        
        // Hash algorithm
        guard offset < data.count else { throw PGPError.invalidMessage }
        self.hashAlgorithm = PGPHashAlgorithm(rawValue: data[offset]) ?? .unknown
        offset += 1
        
        // Hashed subpacket length (2 bytes)
        guard offset + 2 <= data.count else { throw PGPError.invalidMessage }
        let hashedLength = data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        offset += 2
        
        // Hashed subpackets
        if hashedLength > 0 {
            guard offset + Int(hashedLength) <= data.count else { throw PGPError.invalidMessage }
            let hashedData = data.subdata(in: offset..<offset+Int(hashedLength))
            offset += Int(hashedLength)
            hashedSubpackets = try parseSubpackets(from: hashedData)
        }
        
        // Unhashed subpacket length (2 bytes)
        guard offset + 2 <= data.count else { throw PGPError.invalidMessage }
        let unhashedLength = data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        offset += 2
        
        // Unhashed subpackets
        if unhashedLength > 0 {
            guard offset + Int(unhashedLength) <= data.count else { throw PGPError.invalidMessage }
            let unhashedData = data.subdata(in: offset..<offset+Int(unhashedLength))
            offset += Int(unhashedLength)
            unhashedSubpackets = try parseSubpackets(from: unhashedData)
        }
        
        // Signed hash value (2 bytes)
        guard offset + 2 <= data.count else { throw PGPError.invalidMessage }
        self.signedHashValueData = data.subdata(in: offset..<offset+2)
        offset += 2
        
        // Signature MPIs
        let remainingData = data.subdata(in: offset..<data.count)
        try parseSignatureMPIs(from: remainingData)
    }
    
    private func parseSubpackets(from data: Data) throws -> [PGPSignatureSubpacket] {
        var subpackets: [PGPSignatureSubpacket] = []
        var offset = 0
        
        while offset < data.count {
            guard let header = PGPSignatureSubpacketHeader.from(data: data, at: offset) else {
                // Skip invalid subpacket
                offset += 1
                continue
            }
            
            let bodyStart = offset + header.headerLength
            guard bodyStart + header.bodyLength <= data.count else {
                break
            }
            
            let body = data.subdata(in: bodyStart..<bodyStart+header.bodyLength)
            if let subpacket = PGPSignatureSubpacket(header: header, body: body) {
                subpackets.append(subpacket)
            }
            
            offset += header.headerLength + header.bodyLength
        }
        
        return subpackets
    }
    
    private func parseSignatureMPIs(from data: Data) throws {
        var offset = 0
        signatureMPIs = []
        
        switch publicKeyAlgorithm {
        case .rsa, .rsaEncryptOnly, .rsaSignOnly:
            // RSA: one MPI (signature value)
            guard let mpi = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.n, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpi.packetLength
            signatureMPIs.append(mpi)
            
        case .dsa, .ecdsa:
            // DSA/ECDSA: two MPIs (r and s)
            guard let mpiR = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.r, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiR.packetLength
            signatureMPIs.append(mpiR)
            
            guard let mpiS = PGPMPI(mpiData: data, identifier: PGPMPIdentifier.s, at: offset) else {
                throw PGPError.invalidMessage
            }
            offset += mpiS.packetLength
            signatureMPIs.append(mpiS)
            
        default:
            // Other algorithms - store raw data for now
            break
        }
    }
    
    // MARK: - Computed Properties
    
    public var subpackets: [PGPSignatureSubpacket] {
        return hashedSubpackets + unhashedSubpackets
    }
    
    public func subpackets(ofType type: PGPSignatureSubpacketType) -> [PGPSignatureSubpacket] {
        return subpackets.filter { ($0.type.rawValue & 0x7F) == type.rawValue }
    }
    
    public var issuerKeyID: PGPKeyID? {
        let subpackets = subpackets(ofType: .issuerKeyID)
        return subpackets.first?.value as? PGPKeyID
    }
    
    public var creationDate: Date? {
        let subpackets = subpackets(ofType: .signatureCreationTime)
        return subpackets.first?.value as? Date
    }
    
    public var expirationDate: Date? {
        guard let creationDate = creationDate else { return nil }
        let subpackets = subpackets(ofType: .signatureExpirationTime)
        guard let validityPeriod = subpackets.first?.value as? NSNumber,
              validityPeriod.uint32Value > 0 else {
            return nil
        }
        return creationDate.addingTimeInterval(TimeInterval(validityPeriod.uint32Value))
    }
    
    public var isExpired: Bool {
        guard let expirationDate = expirationDate else { return false }
        return expirationDate < Date()
    }
    
    public var isPrimaryUserID: Bool {
        let subpackets = subpackets(ofType: .primaryUserID)
        guard let value = subpackets.first?.value as? NSNumber else {
            return false
        }
        return value.boolValue
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        var body = Data()
        
        body.append(version)
        body.append(type.rawValue)
        body.append(publicKeyAlgorithm.rawValue)
        body.append(hashAlgorithm.rawValue)
        
        // Hashed subpackets
        var hashedData = Data()
        for subpacket in hashedSubpackets {
            hashedData.append(try subpacket.export())
        }
        var hashedLength = UInt16(hashedData.count).bigEndian
        body.append(Data(bytes: &hashedLength, count: 2))
        body.append(hashedData)
        
        // Unhashed subpackets
        var unhashedData = Data()
        for subpacket in unhashedSubpackets {
            unhashedData.append(try subpacket.export())
        }
        var unhashedLength = UInt16(unhashedData.count).bigEndian
        body.append(Data(bytes: &unhashedLength, count: 2))
        body.append(unhashedData)
        
        // Signed hash value
        if let hashValue = signedHashValueData {
            body.append(hashValue)
        } else {
            body.append(Data([0x00, 0x00])) // Placeholder
        }
        
        // Signature MPIs
        for mpi in signatureMPIs {
            body.append(mpi.exportMPI())
        }
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: body.count)
        var result = header
        result.append(body)
        return result
    }
    
    // MARK: - Verification
    
    
    /// Calculate trailer for V4 signatures
    private func calculateTrailer() -> Data {
        // V4 signature trailer: 0x04 0xFF [4-byte length of signed part]
        var trailer = Data()
        trailer.append(0x04)
        trailer.append(0xFF)
        let signedPartLength = buildSignedPart().count
        var length = UInt32(signedPartLength).bigEndian
        trailer.append(Data(bytes: &length, count: 4))
        return trailer
    }
    
    /// Get signature MPI by identifier
    public func signatureMPI(_ identifier: String) -> PGPMPI? {
        return signatureMPIs.first { $0.identifier == identifier }
    }
    
    /// Build data to sign based on signature type
    private func buildDataToSignForType(_ type: PGPSignatureType, inputData: Data?, key: PGPKey?, userID: String?) throws -> Data {
        var toSignData = Data()
        
        switch type {
        case .binaryDocument, .canonicalTextDocument:
            guard let inputData = inputData else {
                throw PGPError.invalidMessage
            }
            toSignData.append(inputData)
            
        case .genericCertificationUserIDandPublicKey,
             .personalCertificationUserIDandPublicKey,
             .casualCertificationUserIDandPublicKey,
             .positiveCertificationUserIDandPublicKey,
             .certificationRevocation:
            // Certification signature - hash starts with key packet
            guard let publicKey = key?.publicKey,
                  let primaryKeyPacket = publicKey.primaryKeyPacket else {
                throw PGPError.general
            }
            // Export key in old-style format (0x99 prefix)
            let keyData = try exportKeyPacketOldStyle(primaryKeyPacket)
            toSignData.append(keyData)
            
            // Add user ID if provided
            if let userID = userID, let userIDData = userID.data(using: .utf8) {
                var userIDPacket = Data()
                userIDPacket.append(0xB4) // Old format tag for User ID
                var length = UInt32(userIDData.count).bigEndian
                userIDPacket.append(Data(bytes: &length, count: 4))
                userIDPacket.append(userIDData)
                toSignData.append(userIDPacket)
            }
            
        case .standalone:
            // Standalone signature - just use input data
            if let inputData = inputData {
                toSignData.append(inputData)
            }
            
        default:
            // For other types, use input data if available
            if let inputData = inputData {
                toSignData.append(inputData)
            }
        }
        
        return toSignData
    }
    
    /// Export key packet in old-style format (with 0x99 prefix)
    private func exportKeyPacketOldStyle(_ keyPacket: PGPPublicKeyPacket) throws -> Data {
        var data = Data()
        data.append(0x99) // Old format marker
        let keyBody = try keyPacket.export()
        // Remove header to get just body
        guard let (bodyData, _, _, _) = PGPPacket.readPacketBody(from: keyBody) else {
            // Fallback: try to extract body manually
            // Skip packet header (usually starts with 0x99 or 0xC0+)
            var offset = 0
            if keyBody.count > 0 && (keyBody[0] & 0x80) != 0 {
                // New format header
                offset = 1
                if (keyBody[0] & 0x40) == 0 {
                    // Old format
                    offset = 2
                } else {
                    // New format - skip length bytes
                    let lengthType = keyBody[0] & 0x03
                    switch lengthType {
                    case 0: offset += 1
                    case 1: offset += 2
                    case 2: offset += 4
                    case 3: offset += 1 // Partial body length
                    default: break
                    }
                }
            }
            let bodyData = keyBody.subdata(in: offset..<keyBody.count)
            var bodyLength = UInt16(bodyData.count).bigEndian
            data.append(Data(bytes: &bodyLength, count: 2))
            data.append(bodyData)
            return data
        }
        var bodyLength = UInt16(bodyData.count).bigEndian
        data.append(Data(bytes: &bodyLength, count: 2))
        data.append(bodyData)
        return data
    }
    
    /// Build signed part data (version + type + algorithm + hash + hashed subpackets)
    private func buildSignedPart() -> Data {
        var data = Data()
        data.append(version)
        data.append(type.rawValue)
        data.append(publicKeyAlgorithm.rawValue)
        data.append(hashAlgorithm.rawValue)
        
        // Hashed subpackets
        var hashedData = Data()
        for subpacket in hashedSubpackets {
            if let subpacketData = try? subpacket.export() {
                hashedData.append(subpacketData)
            }
        }
        var hashedLength = UInt16(hashedData.count).bigEndian
        data.append(Data(bytes: &hashedLength, count: 2))
        data.append(hashedData)
        
        return data
    }
    
    /// Verify signature (basic structure - requires RSA implementation)
    public func verify(data: Data, publicKey: PGPKey, signingKeyPacket: PGPPublicKeyPacket, userID: String? = nil) throws -> Bool {
        // Validate signature type
        if type == .binaryDocument && data.isEmpty {
            throw PGPError.invalidSignature
        }
        
        // Build data to sign based on signature type
        let toSignData = try buildDataToSignForType(type, inputData: data, key: publicKey, userID: userID)
        
        // Build signed part
        let signedPartData = buildSignedPart()
        
        // Calculate trailer
        let trailerData = calculateTrailer()
        
        // Build hash input: toSignData + signedPartData + trailerData
        var toHashData = toSignData
        toHashData.append(signedPartData)
        toHashData.append(trailerData)
        
        // Calculate hash
        let calculatedHash = toHashData.hashedWithAlgorithm(hashAlgorithm)
        let calculatedHashValue = calculatedHash.prefix(2)
        
        // Verify signed hash value
        guard let signedHashValue = signedHashValueData,
              signedHashValue == calculatedHashValue else {
            throw PGPError.invalidSignature
        }
        
        // Verify signature based on algorithm
        switch signingKeyPacket.publicKeyAlgorithm {
        case .rsa, .rsaSignOnly, .rsaEncryptOnly:
            return try verifyRSASignature(toHashData: toHashData, signingKeyPacket: signingKeyPacket)
            
        case .dsa, .ecdsa:
            // TODO: Implement DSA/ECDSA verification
            throw PGPError.general
            
        default:
            throw PGPError.general
        }
    }
    
    /// Verify RSA signature
    private func verifyRSASignature(toHashData: Data, signingKeyPacket: PGPPublicKeyPacket) throws -> Bool {
        // Get signature MPI
        guard let signatureMPI = signatureMPI(PGPMPIdentifier.n) else {
            throw PGPError.invalidSignature
        }
        
        // Get signature body data (raw bytes)
        let encryptedEmData = signatureMPI.bodyData()
        
        // Decrypt using public key (this is signature verification)
        guard let decryptedEmData = PGPRSA.publicDecrypt(encryptedEmData, withPublicKeyPacket: signingKeyPacket) else {
            throw PGPError.invalidSignature
        }
        
        // Calculate expected EM (PKCS EMSA padded hash)
        guard let mpiN = signingKeyPacket.mpi(identifier: PGPMPIdentifier.n) else {
            throw PGPError.invalidSignature
        }
        let keySize = (mpiN.bigNum.bitsCount + 7) / 8
        let expectedEmData = try PGPPKCSEmsa.encode(hashAlgorithm: hashAlgorithm,
                                                    message: toHashData,
                                                    encodedMessageLength: keySize)
        
        // Compare
        guard decryptedEmData == expectedEmData else {
            throw PGPError.invalidSignature
        }
        
        return true
    }
    
    /// Verify signature with public key (convenience method)
    public func verify(data: Data, publicKey: PGPKey, userID: String? = nil) throws -> Bool {
        guard let issuerKeyID = issuerKeyID else {
            throw PGPError.invalidSignature
        }
        
        // Find signing key packet
        guard let publicKeyPacket = publicKey.publicKey?.primaryKeyPacket,
              publicKeyPacket.keyID == issuerKeyID else {
            throw PGPError.invalidSignature
        }
        
        return try verify(data: data, publicKey: publicKey, signingKeyPacket: publicKeyPacket, userID: userID)
    }
}

