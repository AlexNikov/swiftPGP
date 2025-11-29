//
//  PGPFoundation.swift
//  SwiftPGP
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

import Foundation
import CommonCrypto
import Security
import Security

/// Foundation utilities for SwiftPGP
public struct PGPFoundation {
    
    /// Safe cast function
    public static func cast<T>(_ obj: Any?, to type: T.Type) -> T? {
        return obj as? T
    }
    
    /// Compare two objects for equality
    public static func equalObjects(_ obj1: Any?, _ obj2: Any?) -> Bool {
        // Check for nil
        guard let obj1 = obj1, let obj2 = obj2 else {
            return obj1 == nil && obj2 == nil
        }
        
        // Use NSObject's isEqual if available
        if let nsObj1 = obj1 as? NSObject, let nsObj2 = obj2 as? NSObject {
            return nsObj1 === nsObj2 || nsObj1.isEqual(nsObj2)
        }
        
        // Fallback to string comparison
        return String(describing: obj1) == String(describing: obj2)
    }
}

// MARK: - Data Extensions

public extension Data {
    
    /// Calculate CRC24 checksum for OpenPGP armor
    var pgpCRC24: UInt32 {
        let CRC24_POLY: UInt32 = 0x1864cfb
        let CRC24_INIT: UInt32 = 0xB704CE
        
        var crc = CRC24_INIT
        
        for byte in self {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if (crc & 0x1000000) != 0 {
                    crc ^= CRC24_POLY
                }
            }
        }
        
        return crc & 0xFFFFFF
    }
    
    /// Calculate 16-bit checksum (sum of all octets mod 65536)
    var pgpChecksum: UInt16 {
        var sum: UInt32 = 0
        for byte in self {
            sum = (sum + UInt32(byte))
        }
        return UInt16(sum % 65536)
    }
    
    /// Calculate SHA1 hash
    var pgpSHA1: Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA1(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return Data(digest)
    }
    
    var pgpMD5: Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_MD5(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return Data(digest)
    }
    
    var pgpSHA224: Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA224(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return Data(digest)
    }
    
    var pgpSHA256: Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return Data(digest)
    }
    
    var pgpSHA384: Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA384(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return Data(digest)
    }
    
    var pgpSHA512: Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA512(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return Data(digest)
    }
    
    var pgpRIPEMD160: Data {
        // RIPEMD160 is not available in CommonCrypto, use SHA1 as fallback
        // TODO: Implement RIPEMD160 or use external library
        return self.pgpSHA1
    }
    
    /// Hash data with specified algorithm
    func hashedWithAlgorithm(_ algorithm: PGPHashAlgorithm) -> Data {
        switch algorithm {
        case .md5: return self.pgpMD5
        case .sha1: return self.pgpSHA1
        case .sha224: return self.pgpSHA224
        case .sha256: return self.pgpSHA256
        case .sha384: return self.pgpSHA384
        case .sha512: return self.pgpSHA512
        case .ripemd160: return self.pgpRIPEMD160
        default: return self.pgpSHA1
        }
    }
}

// MARK: - Crypto Utils

public class PGPCryptoUtils {
    
    /// Generate secure random data
    public static func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, length, bytes.baseAddress!)
        }
        assert(status == errSecSuccess, "Failed to generate secure random bytes")
        return data
    }
    
    /// Get key size for symmetric algorithm
    public static func keySizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .idea: return 16
        case .tripleDES: return 24
        case .cast5: return 16
        case .blowfish: return 16
        case .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        case .twofish256: return 32
        case .plaintext: return 0
        default: return 16
        }
    }
    
    /// Get block size for symmetric algorithm
    public static func blockSizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .idea, .tripleDES, .cast5, .blowfish: return 8
        case .aes128, .aes192, .aes256, .twofish256: return 16
        case .plaintext: return 0
        default: return 16
        }
    }
}
