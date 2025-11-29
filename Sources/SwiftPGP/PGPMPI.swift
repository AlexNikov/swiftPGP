//
//  PGPMPI.swift
//  SwiftPGP
//

import Foundation

/// MPI (Multiprecision Integer) identifiers
public struct PGPMPIdentifier {
    public static let n = "N"  // RSA modulus
    public static let e = "E"  // RSA public exponent
    public static let p = "P"  // Prime
    public static let g = "G"  // Generator
    public static let q = "Q"  // ECC public key
    public static let d = "D"  // ECC secret key / RSA private exponent
    public static let u = "U"
    public static let x = "X"  // Secret
    public static let r = "R"
    public static let s = "S"
    public static let y = "Y"  // Public key (Elgamal)
    public static let m = "M"
    public static let v = "V"  // EC public point
}

/// Multiprecision Integer - used to hold large integers for cryptographic calculations
public class PGPMPI: NSObject, NSCopying {
    
    public let identifier: String
    public let bigNum: PGPBigNum
    public let packetLength: Int
    
    /// Initialize MPI from raw data (will be converted to big-endian)
    public init(data: Data, identifier: String) {
        self.identifier = identifier
        // Ensure data is big-endian (remove leading zeros)
        var trimmed = data
        while !trimmed.isEmpty && trimmed.first == 0 {
            trimmed = trimmed.dropFirst()
        }
        if trimmed.isEmpty {
            trimmed = Data([0])
        }
        self.bigNum = PGPBigNum(data: trimmed)
        // Packet length = 2 bytes (bit count) + data length
        self.packetLength = 2 + trimmed.count
        super.init()
    }
    
    /// Initialize MPI from PGPBigNum
    public init(bigNum: PGPBigNum, identifier: String) {
        self.identifier = identifier
        self.bigNum = bigNum
        self.packetLength = 2 + bigNum.bigEndianData.count
        super.init()
    }
    
    /// Parse MPI from PGP packet data at given position
    public init?(mpiData: Data, identifier: String, at position: Int) {
        guard position + 2 <= mpiData.count else {
            return nil
        }
        
        // Read bit count (2 bytes, big-endian)
        let bitsData = mpiData.subdata(in: position..<position+2)
        let bits = bitsData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        
        // Calculate byte count: (bits + 7) / 8
        let byteCount = (Int(bits) + 7) / 8
        
        guard position + 2 + byteCount <= mpiData.count else {
            return nil
        }
        
        // Read the actual number
        let numberData = mpiData.subdata(in: position+2..<position+2+byteCount)
        
        self.identifier = identifier
        self.bigNum = PGPBigNum(data: numberData)
        self.packetLength = 2 + byteCount
        super.init()
    }
    
    /// Export MPI in PGP format: 2 bytes (bit count) + number bytes
    public func exportMPI() -> Data {
        let numberData = bigNum.bigEndianData
        let bits = UInt16(bigNum.bitsCount)
        
        var result = Data()
        var bitsBE = bits.bigEndian
        result.append(Data(bytes: &bitsBE, count: 2))
        result.append(numberData)
        
        return result
    }
    
    /// Get just the body data (without the 2-byte header)
    public func bodyData() -> Data {
        return bigNum.bigEndianData
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        return PGPMPI(bigNum: bigNum, identifier: identifier)
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? PGPMPI else {
            return false
        }
        return identifier == other.identifier && bigNum == other.bigNum
    }
    
    public override var hash: Int {
        var hasher = Hasher()
        hasher.combine(identifier)
        hasher.combine(bigNum)
        return hasher.finalize()
    }
}

