//
//  PGPBigNum.swift
//  SwiftPGP
//

import Foundation

/// Big number representation for PGP operations
/// Note: This is a simplified implementation. For full cryptographic operations,
/// integration with OpenSSL or CryptoKit would be needed.
public class PGPBigNum: NSObject, NSCopying {
    
    private let data: Data
    
    public var bitsCount: Int {
        if data.isEmpty {
            return 0
        }
        // Count bits: find first non-zero byte, then count bits in that byte
        var firstNonZero = 0
        for (index, byte) in data.enumerated() {
            if byte != 0 {
                firstNonZero = index
                break
            }
        }
        
        let firstByte = data[firstNonZero]
        var bits = (data.count - firstNonZero - 1) * 8
        
        // Count leading zeros in first byte
        var temp = firstByte
        while temp != 0 {
            bits += 1
            temp >>= 1
        }
        
        return bits
    }
    
    public var bytesCount: Int {
        // Remove leading zeros
        var firstNonZero = 0
        for (index, byte) in data.enumerated() {
            if byte != 0 {
                firstNonZero = index
                break
            }
        }
        return data.count - firstNonZero
    }
    
    public var bigEndianData: Data {
        // Return data with leading zeros removed
        var firstNonZero = 0
        for (index, byte) in data.enumerated() {
            if byte != 0 {
                firstNonZero = index
                break
            }
        }
        if firstNonZero < data.count {
            return data.subdata(in: firstNonZero..<data.count)
        }
        return Data([0])
    }
    
    public init(data: Data) {
        self.data = data
        super.init()
    }
    
    public convenience init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }
        
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return nil
            }
            bytes.append(byte)
            index = nextIndex
        }
        
        self.init(data: Data(bytes))
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        return PGPBigNum(data: self.data)
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? PGPBigNum else {
            return false
        }
        return self.bigEndianData == other.bigEndianData
    }
    
    public override var hash: Int {
        var hasher = Hasher()
        hasher.combine(bigEndianData)
        return hasher.finalize()
    }
}

