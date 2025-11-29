//
//  PGPSignatureSubpacketHeader.swift
//  SwiftPGP
//

import Foundation

/// Signature Subpacket Header
public struct PGPSignatureSubpacketHeader {
    public let type: PGPSignatureSubpacketType
    public let headerLength: Int
    public let bodyLength: Int
    
    /// Parse subpacket header from data
    public static func from(data: Data, at position: Int) -> PGPSignatureSubpacketHeader? {
        guard position < data.count else { return nil }
        
        let typeByte = data[position]
        let type = PGPSignatureSubpacketType(rawValue: typeByte & 0x7F) ?? .unknown
        var offset = position + 1
        
        var bodyLength: Int = 0
        var headerLength = 1 // type byte
        
        // Parse length (can be 1, 2, or 5 bytes)
        if offset >= data.count {
            return nil
        }
        
        let firstLengthByte = Int(data[offset])
        offset += 1
        headerLength += 1
        
        if firstLengthByte < 192 {
            // One-octet length
            bodyLength = firstLengthByte
        } else if firstLengthByte >= 192 && firstLengthByte < 255 {
            // Two-octet length
            guard offset < data.count else { return nil }
            let secondLengthByte = Int(data[offset])
            offset += 1
            headerLength += 1
            bodyLength = ((firstLengthByte - 192) << 8) + secondLengthByte + 192
        } else if firstLengthByte == 255 {
            // Five-octet length
            guard offset + 4 <= data.count else { return nil }
            let lengthData = data.subdata(in: offset..<offset+4)
            bodyLength = Int(lengthData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
            headerLength += 4
        } else {
            return nil
        }
        
        return PGPSignatureSubpacketHeader(type: type, headerLength: headerLength, bodyLength: bodyLength)
    }
}

