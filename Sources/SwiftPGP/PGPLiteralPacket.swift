//
//  PGPLiteralPacket.swift
//  SwiftPGP
//

import Foundation

/// Literal Packet Format
public enum PGPLiteralPacketFormat: UInt8 {
    case binary = 0x62 // 'b'
    case text = 0x74   // 't'
    case textUTF8 = 0x75 // 'u'
}

/// Literal Data Packet (Tag 11)
public class PGPLiteralPacket: PGPPacket {
    
    public var format: PGPLiteralPacketFormat = .binary
    public var timestamp: Date = Date()
    public var filename: String?
    public var literalRawData: Data?
    
    public init() {
        super.init(tag: .literalData)
    }
    
    public init(data: Data) {
        self.literalRawData = data
        super.init(tag: .literalData)
    }
    
    public static func literalPacket(format: PGPLiteralPacketFormat, withData data: Data) -> PGPLiteralPacket {
        let packet = PGPLiteralPacket(data: data)
        packet.format = format
        return packet
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        // Format (1 byte)
        guard offset < data.count else { throw PGPError.invalidMessage }
        guard let format = PGPLiteralPacketFormat(rawValue: data[offset]) else {
            throw PGPError.invalidMessage
        }
        self.format = format
        offset += 1
        
        // Filename length (1 byte)
        guard offset < data.count else { throw PGPError.invalidMessage }
        let filenameLength = Int(data[offset])
        offset += 1
        
        // Filename
        if filenameLength > 0 {
            guard offset + filenameLength <= data.count else { throw PGPError.invalidMessage }
            let filenameData = data.subdata(in: offset..<offset+filenameLength)
            if let filenameString = String(data: filenameData, encoding: .utf8) {
                self.filename = filenameString
            }
            offset += filenameLength
        }
        
        // Timestamp (4 bytes)
        guard offset + 4 <= data.count else { throw PGPError.invalidMessage }
        let timestampData = data.subdata(in: offset..<offset+4)
        let timestamp = timestampData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        self.timestamp = Date(timeIntervalSince1970: TimeInterval(timestamp))
        offset += 4
        
        // Literal data (remaining bytes)
        if offset < data.count {
            self.literalRawData = data.subdata(in: offset..<data.count)
        }
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        guard let literalData = literalRawData else {
            throw PGPError.invalidMessage
        }
        
        var body = Data()
        body.append(format.rawValue)
        
        // Filename
        if let filename = filename, let filenameData = filename.data(using: .utf8) {
            body.append(UInt8(filenameData.count))
            body.append(filenameData)
        } else {
            body.append(0x00) // Zero length
        }
        
        // Timestamp
        var timestamp = UInt32(self.timestamp.timeIntervalSince1970).bigEndian
        body.append(Data(bytes: &timestamp, count: 4))
        
        // Literal data
        body.append(literalData)
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: body.count)
        var result = header
        result.append(body)
        return result
    }
}

