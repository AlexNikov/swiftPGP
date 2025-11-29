//  PGPFingerprint.swift
//  SwiftPGP

import Foundation

/// PGP Fingerprint
public class PGPFingerprint: NSObject, NSCopying {
    
    public let keyData: Data
    public let fingerprintData: Data
    
    public var hexString: String {
        return fingerprintData.map { String(format: "%02X", $0) }.joined()
    }
    
    /// Initialize with key data (will compute SHA1 hash)
    public init(keyData: Data) {
        self.keyData = keyData
        self.fingerprintData = keyData.pgpSHA1
        super.init()
    }
    
    /// Initialize with pre-computed fingerprint data
    public init(fingerprintData: Data) {
        self.keyData = Data()
        self.fingerprintData = fingerprintData
        super.init()
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        return PGPFingerprint(fingerprintData: fingerprintData)
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? PGPFingerprint else {
            return false
        }
        return self.fingerprintData == other.fingerprintData
    }
    
    public override var hash: Int {
        var hasher = Hasher()
        hasher.combine(fingerprintData)
        return hasher.finalize()
    }
    
    /// Export V4 hashed data (version byte + 20 bytes of SHA1)
    public func exportV4HashedData() -> Data {
        var result = Data()
        result.append(0x04) // Version 4
        result.append(fingerprintData)
        return result
    }
}

