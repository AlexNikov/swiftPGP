//
//  PGPPacket.swift
//  SwiftPGP
//

import Foundation

/// Base class for all PGP packets
public class PGPPacket: NSObject, NSCopying, PGPExportable {
    
    public let tag: PGPPacketTag
    public var indeterminateLength: Bool = false
    
    public init(tag: PGPPacketTag) {
        self.tag = tag
        super.init()
    }
    
    // MARK: - PGPExportable
    
    public func export() throws -> Data {
        fatalError("Subclasses must implement export()")
    }
    
    // MARK: - NSCopying
    
    public func copy(with zone: NSZone? = nil) -> Any {
        return PGPPacket(tag: self.tag)
    }
    
    // MARK: - Parsing
    
    /// Parse packet body
    public func parse(data: Data) throws {
        // Default implementation does nothing
    }
    
    // MARK: - Packet Header Parsing
    
    /// Read packet body from data
    /// - Parameters:
    ///   - data: Data starting with packet header
    /// - Returns: Packet body data, tag, header length, and consumed bytes
    public static func readPacketBody(from data: Data) -> (bodyData: Data, tag: PGPPacketTag, headerLength: Int, consumedBytes: Int)? {
        guard !data.isEmpty else { return nil }
        
        var offset = 0
        let tagByte = data[offset]
        offset += 1
        
        // Check if it's a valid PGP packet (Bit 7 must be 1)
        guard (tagByte & 0x80) != 0 else { return nil }
        
        var packetTag: PGPPacketTag = .invalid
        var bodyLength: Int = 0
        var isIndeterminate = false
        
        // Check format (Old vs New)
        if (tagByte & 0x40) != 0 {
            // New Format (Bit 6 is 1)
            packetTag = PGPPacketTag(rawValue: tagByte & 0x3F) ?? .invalid
            
            guard offset < data.count else { return nil }
            let lengthByte1 = Int(data[offset])
            offset += 1
            
            if lengthByte1 < 192 {
                // One-octet length
                bodyLength = lengthByte1
            } else if lengthByte1 >= 192 && lengthByte1 < 224 {
                // Two-octet length
                guard offset < data.count else { return nil }
                let lengthByte2 = Int(data[offset])
                offset += 1
                bodyLength = ((lengthByte1 - 192) << 8) + lengthByte2 + 192
            } else if lengthByte1 == 255 {
                // Five-octet length
                guard offset + 4 <= data.count else { return nil }
                let lengthData = data.subdata(in: offset..<offset+4)
                bodyLength = Int(lengthData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
                offset += 4
            } else {
                // Partial body length (unsupported for simple parsing)
                // 224 <= lengthByte1 < 255
                isIndeterminate = true
                // TODO: Handle partial length properly
                return nil 
            }
            
        } else {
            // Old Format (Bit 6 is 0)
            packetTag = PGPPacketTag(rawValue: (tagByte >> 2) & 0x0F) ?? .invalid
            let lengthType = tagByte & 0x03
            
            switch lengthType {
            case 0:
                // 1 byte length
                guard offset < data.count else { return nil }
                bodyLength = Int(data[offset])
                offset += 1
            case 1:
                // 2 byte length
                guard offset + 2 <= data.count else { return nil }
                bodyLength = Int(data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
                offset += 2
            case 2:
                // 4 byte length
                guard offset + 4 <= data.count else { return nil }
                bodyLength = Int(data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
                offset += 4
            case 3:
                // Indeterminate length (until EOF)
                isIndeterminate = true
                bodyLength = data.count - offset
            default:
                return nil
            }
        }
        
        guard offset + bodyLength <= data.count else { return nil }
        let bodyData = data.subdata(in: offset..<offset+bodyLength)
        
        return (bodyData, packetTag, offset, offset + bodyLength)
    }
    
    /// Build packet header
    public static func buildHeader(tag: PGPPacketTag, bodyLength: Int) -> Data {
        var header = Data()
        
        // Always use New Format for writing if possible, but PGP 2.x compatibility might require Old Format.
        // For simplicity, implementing New Format here as it's standard for OpenPGP.
        
        // New Format: Bit 7=1, Bit 6=1, Tag
        let tagByte = 0xC0 | (tag.rawValue & 0x3F)
        header.append(tagByte)
        
        if bodyLength < 192 {
            header.append(UInt8(bodyLength))
        } else if bodyLength < 8384 {
            let len = bodyLength - 192
            header.append(UInt8((len >> 8) + 192))
            header.append(UInt8(len & 0xFF))
        } else {
            header.append(255)
            var len = UInt32(bodyLength).bigEndian
            let lenData = Data(bytes: &len, count: 4)
            header.append(lenData)
        }
        
        return header
    }
}

