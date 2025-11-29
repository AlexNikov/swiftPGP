//
//  PGPModificationDetectionCodePacket.swift
//  SwiftPGP
//

import Foundation

/// Modification Detection Code Packet (Tag 19)
public class PGPModificationDetectionCodePacket: PGPPacket {
    
    public var validHash: Data = Data(count: 20) // SHA-1 hash (20 bytes)
    
    public init() {
        super.init(tag: .modificationDetectionCode)
    }
    
    public init(hash: Data) {
        super.init(tag: .modificationDetectionCode)
        self.validHash = hash
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard data.count == 20 else { throw PGPError.invalidMessage }
        self.validHash = data
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: validHash.count)
        var result = header
        result.append(validHash)
        return result
    }
    
    public override func copy(with zone: NSZone? = nil) -> Any {
        return PGPModificationDetectionCodePacket(hash: self.validHash)
    }
}
