//  PGPFingerprint.swift
//  SwiftPGP

import Foundation

/// PGP Fingerprint
public class PGPFingerprint: NSObject, NSCopying {
    
    public let fingerprintData: Data
    
    public var hexString: String {
        return fingerprintData.map { String(format: "%02X", $0) }.joined()
    }
    
    public init(fingerprintData: Data) {
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
        return fingerprintData.hashValue
    }
}

