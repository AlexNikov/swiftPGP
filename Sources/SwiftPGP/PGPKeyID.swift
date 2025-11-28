//  PGPKeyID.swift
//  SwiftPGP

import Foundation

/// The eight-octet Key ID
public class PGPKeyID: NSObject, NSCopying {
    
    /// The eight-octet Key identifier
    public let longIdentifier: String
    
    /// The four-octet Key identifier
    public let shortIdentifier: String
    
    /// Initialize with eight-octet key identifier
    public init?(longKey data: Data) {
        guard data.count >= 8 else {
            return nil
        }
        
        // Extract long identifier (8 bytes)
        let longData = data.prefix(8)
        self.longIdentifier = longData.map { String(format: "%02X", $0) }.joined()
        
        // Extract short identifier (last 4 bytes)
        let shortData = longData.suffix(4)
        self.shortIdentifier = shortData.map { String(format: "%02X", $0) }.joined()
        
        super.init()
    }
    
    /// Initialize with fingerprint
    public init(fingerprint: PGPFingerprint) {
        // Extract key ID from fingerprint (last 8 bytes)
        let fingerprintData = fingerprint.fingerprintData
        guard fingerprintData.count >= 8 else {
            self.longIdentifier = ""
            self.shortIdentifier = ""
            super.init()
            return
        }
        
        let keyIDData = fingerprintData.suffix(8)
        self.longIdentifier = keyIDData.map { String(format: "%02X", $0) }.joined()
        
        // Short identifier is last 4 bytes
        let shortData = keyIDData.suffix(4)
        self.shortIdentifier = shortData.map { String(format: "%02X", $0) }.joined()
        
        super.init()
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        let data = Data(hexString: longIdentifier) ?? Data()
        return PGPKeyID(longKey: data) ?? self
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? PGPKeyID else {
            return false
        }
        return self.longIdentifier == other.longIdentifier
    }
    
    public override var hash: Int {
        return longIdentifier.hashValue
    }
}

// MARK: - Data Extension for Hex String

extension Data {
    init?(hexString: String) {
        let hexString = hexString.replacingOccurrences(of: " ", with: "")
        guard hexString.count % 2 == 0 else { return nil }
        
        var data = Data()
        var index = hexString.startIndex
        
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            let byteString = hexString[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
}

