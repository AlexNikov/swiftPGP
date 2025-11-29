//
//  PGPSignatureSubpacket.swift
//  SwiftPGP
//

import Foundation

/// Signature Subpacket
public class PGPSignatureSubpacket: NSObject, NSCopying, PGPExportable {
    
    public let type: PGPSignatureSubpacketType
    public var value: Any?
    public let length: Int
    public var isCritical: Bool {
        return (type.rawValue & 0x80) != 0
    }
    
    public init(type: PGPSignatureSubpacketType, value: Any? = nil) {
        self.type = type
        self.value = value
        // Calculate length (header + body)
        var bodyLength = 0
        if let data = value as? Data {
            bodyLength = data.count
        } else if let string = value as? String {
            bodyLength = string.data(using: .utf8)?.count ?? 0
        } else if let number = value as? NSNumber {
            bodyLength = 4 // UInt32
        } else if let date = value as? Date {
            bodyLength = 4 // UInt32 timestamp
        } else if let keyID = value as? PGPKeyID {
            bodyLength = 8 // Key ID is 8 bytes
        }
        
        // Header: 1 byte type + length encoding (1-5 bytes)
        var headerLength = 1
        if bodyLength < 192 {
            headerLength += 1
        } else if bodyLength < 8384 {
            headerLength += 2
        } else {
            headerLength += 5
        }
        
        self.length = headerLength + bodyLength
        super.init()
    }
    
    /// Parse subpacket from data
    public init?(header: PGPSignatureSubpacketHeader, body: Data) {
        self.type = header.type
        self.length = header.headerLength + header.bodyLength
        
        // Parse body based on type
        let actualType = PGPSignatureSubpacketType(rawValue: type.rawValue & 0x7F) ?? .unknown
        
        switch actualType {
        case .signatureCreationTime:
            // 4-byte timestamp
            guard body.count >= 4 else { return nil }
            let timestamp = body.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            self.value = Date(timeIntervalSince1970: TimeInterval(timestamp))
            
        case .signatureExpirationTime, .keyExpirationTime:
            // 4-byte validity period
            guard body.count >= 4 else { return nil }
            let validity = body.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            self.value = NSNumber(value: validity)
            
        case .issuerKeyID:
            // 8-byte key ID
            guard body.count >= 8 else { return nil }
            if let keyID = PGPKeyID(longKey: body.prefix(8)) {
                self.value = keyID
            } else {
                return nil
            }
            
        case .primaryUserID:
            // 1-byte boolean
            guard body.count >= 1 else { return nil }
            self.value = NSNumber(value: body[0] != 0)
            
        case .signerUserID, .preferredKeyServer, .policyURI:
            // UTF-8 string
            if let string = String(data: body, encoding: .utf8) {
                self.value = string
            } else {
                return nil
            }
            
        default:
            // Store as raw data for unknown types
            self.value = body
        }
        
        super.init()
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        let copy = PGPSignatureSubpacket(type: type, value: value)
        return copy
    }
    
    public func export() throws -> Data {
        var data = Data()
        
        // Type byte
        data.append(type.rawValue)
        
        // Body data
        var bodyData = Data()
        if let dataValue = value as? Data {
            bodyData = dataValue
        } else if let string = value as? String {
            bodyData = string.data(using: .utf8) ?? Data()
        } else if let number = value as? NSNumber {
            var num = UInt32(number.uint32Value).bigEndian
            bodyData = Data(bytes: &num, count: 4)
        } else if let date = value as? Date {
            var timestamp = UInt32(date.timeIntervalSince1970).bigEndian
            bodyData = Data(bytes: &timestamp, count: 4)
        } else if let keyID = value as? PGPKeyID {
            if let keyIDData = Data(hexString: keyID.longIdentifier) {
                bodyData = keyIDData.prefix(8)
            }
        }
        
        // Length encoding
        let bodyLength = bodyData.count
        if bodyLength < 192 {
            data.append(UInt8(bodyLength))
        } else if bodyLength < 8384 {
            let len = bodyLength - 192
            data.append(UInt8((len >> 8) + 192))
            data.append(UInt8(len & 0xFF))
        } else {
            data.append(255)
            var len = UInt32(bodyLength).bigEndian
            data.append(Data(bytes: &len, count: 4))
        }
        
        data.append(bodyData)
        
        return data
    }
}

