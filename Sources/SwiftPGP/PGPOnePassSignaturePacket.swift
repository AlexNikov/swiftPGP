//
//  PGPOnePassSignaturePacket.swift
//  SwiftPGP
//

import Foundation

/// One-Pass Signature Packet (Tag 4)
public class PGPOnePassSignaturePacket: PGPPacket {
    
    public var version: UInt8 = 3
    public var signatureType: PGPSignatureType = .binaryDocument
    public var hashAlgorithm: PGPHashAlgorithm = .sha1
    public var publicKeyAlgorithm: PGPPublicKeyAlgorithm = .rsa
    public var keyID: PGPKeyID?
    public var nested: Bool = true
    
    public init() {
        super.init(tag: .onePassSignature)
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        self.version = data[offset]
        offset += 1
        
        self.signatureType = PGPSignatureType(rawValue: data[offset]) ?? .binaryDocument
        offset += 1
        
        self.hashAlgorithm = PGPHashAlgorithm(rawValue: data[offset]) ?? .sha1
        offset += 1
        
        self.publicKeyAlgorithm = PGPPublicKeyAlgorithm(rawValue: data[offset]) ?? .rsa
        offset += 1
        
        guard offset + 8 <= data.count else { throw PGPError.invalidMessage }
        let keyIDData = data.subdata(in: offset..<offset+8)
        self.keyID = PGPKeyID(longKey: keyIDData)
        offset += 8
        
        let nestedByte = data[offset]
        self.nested = nestedByte != 0
        offset += 1
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        var body = Data()
        body.append(version)
        body.append(signatureType.rawValue)
        body.append(hashAlgorithm.rawValue)
        body.append(publicKeyAlgorithm.rawValue)
        
        if let keyID = keyID, let keyIDData = Data(hexString: keyID.longIdentifier) {
            body.append(keyIDData.prefix(8))
        } else {
            body.append(Data(repeating: 0, count: 8))
        }
        
        body.append(nested ? 1 : 0)
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: body.count)
        var result = header
        result.append(body)
        return result
    }
}
