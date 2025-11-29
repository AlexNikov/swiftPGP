//
//  PGPS2K.swift
//  SwiftPGP
//

import Foundation
import CommonCrypto

/// String-to-Key (S2K) specifier - converts passphrase to encryption key
public class PGPS2K: NSObject, NSCopying, PGPExportable {
    
    private static let saltSize = 8
    private static let defaultIterationsCount: UInt32 = 215
    
    public let specifier: PGPS2KSpecifier
    public let hashAlgorithm: PGPHashAlgorithm
    public var salt: Data
    public var iterationsCount: UInt32
    
    public init(specifier: PGPS2KSpecifier, hashAlgorithm: PGPHashAlgorithm) {
        self.specifier = specifier
        self.hashAlgorithm = hashAlgorithm
        self.salt = Data(repeating: 0, count: PGPS2K.saltSize)
        self.iterationsCount = PGPS2K.defaultIterationsCount
        super.init()
    }
    
    /// Parse S2K from data at given position
    public static func s2k(from data: Data, at position: Int) -> (s2k: PGPS2K, length: Int)? {
        guard position + 2 <= data.count else { return nil }
        
        let specifier = PGPS2KSpecifier(rawValue: data[position]) ?? .simple
        let hashAlgo = PGPHashAlgorithm(rawValue: data[position + 1]) ?? .sha1
        
        let s2k = PGPS2K(specifier: specifier, hashAlgorithm: hashAlgo)
        var offset = position + 2
        
        // Read salt if needed
        if specifier == .salted || specifier == .iteratedAndSalted {
            guard offset + PGPS2K.saltSize <= data.count else { return nil }
            s2k.salt = data.subdata(in: offset..<offset + PGPS2K.saltSize)
            offset += PGPS2K.saltSize
        }
        
        // Read iterations count if needed
        if specifier == .iteratedAndSalted {
            guard offset < data.count else { return nil }
            s2k.iterationsCount = UInt32(data[offset])
            offset += 1
        }
        
        // Handle GNU Dummy and DivertToCard
        if specifier == .gnuDummy || specifier == .divertToCard {
            guard offset + 4 <= data.count else { return nil }
            let gnuString = String(data: data.subdata(in: offset..<offset+3), encoding: .ascii)
            if gnuString == "GNU" {
                offset += 4
            }
        }
        
        return (s2k, offset - position)
    }
    
    /// Calculate coded iterations count
    private func codedIterationsCount() -> UInt32 {
        if iterationsCount > 65011712 {
            return 255
        }
        return (16 + (iterationsCount & 15)) << ((iterationsCount >> 4) + 6)
    }
    
    /// Build key data for passphrase
    private func buildKeyData(passphrase: Data, prefix: Data? = nil, salt: Data, codedCount: UInt32) -> Data? {
        var dataToHash = Data()
        
        switch specifier {
        case .simple:
            if let prefix = prefix {
                dataToHash.append(prefix)
            }
            dataToHash.append(passphrase)
            
        case .salted:
            if let prefix = prefix {
                dataToHash.append(prefix)
            }
            dataToHash.append(salt)
            dataToHash.append(passphrase)
            
        case .iteratedAndSalted:
            let baseData = salt + passphrase
            var totalLength: UInt32 = 0
            
            // First add prefix
            if let prefix = prefix {
                dataToHash.append(prefix)
            }
            
            // Then iterate baseData
            while totalLength < codedCount {
                let remaining = codedCount - totalLength
                if remaining >= UInt32(baseData.count) {
                    dataToHash.append(baseData)
                    totalLength += UInt32(baseData.count)
                } else {
                    dataToHash.append(baseData.prefix(Int(remaining)))
                    totalLength += remaining
                }
            }
            
        case .gnuDummy, .divertToCard:
            // No secret key available
            return nil
            
        default:
            return nil
        }
        
        // Hash the data
        return hashData(dataToHash, algorithm: hashAlgorithm)
    }
    
    /// Hash data using specified algorithm
    private func hashData(_ data: Data, algorithm: PGPHashAlgorithm) -> Data? {
        switch algorithm {
        case .sha1:
            return data.pgpSHA1
        case .sha256:
            return data.pgpSHA256
        case .sha512:
            return data.pgpSHA512
        default:
            // Fallback to SHA1
            return data.pgpSHA1
        }
    }
    
    /// Produce session key from passphrase
    public func produceSessionKey(passphrase: String, symmetricAlgorithm: PGPSymmetricAlgorithm) -> Data? {
        guard let passphraseData = passphrase.data(using: .utf8) else {
            return nil
        }
        
        let codedCount = codedIterationsCount()
        var hashData = buildKeyData(passphrase: passphraseData, prefix: nil, salt: salt, codedCount: codedCount)
        
        guard let initialHash = hashData else {
            return nil
        }
        
        // Get required key size
        let keySize = keySizeOfSymmetricAlgorithm(symmetricAlgorithm)
        
        // If hash is shorter than key size, expand it
        if initialHash.count < keySize {
            var expandedHash = initialHash
            var level = 1
            
            while expandedHash.count < keySize {
                var prefix = Data(repeating: 0, count: level)
                if let additionalHash = buildKeyData(passphrase: passphraseData, prefix: prefix, salt: salt, codedCount: codedCount) {
                    expandedHash.append(additionalHash)
    }
                level += 1
            }
            
            hashData = expandedHash
        }
        
        // Return first keySize bytes
        return hashData?.prefix(keySize)
        }
    
    /// Get key size for symmetric algorithm
    private func keySizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        case .cast5: return 16
        case .blowfish: return 16
        case .twofish256: return 32
        case .tripleDES: return 24
        case .idea: return 16
        case .plaintext: return 0
        default: return 16
        }
    }
    
    // MARK: - PGPExportable
    
    public func export() throws -> Data {
        var data = Data()
        data.append(specifier.rawValue)
        data.append(hashAlgorithm.rawValue)
        
        if specifier == .salted || specifier == .iteratedAndSalted {
            data.append(salt)
        }
        
        if specifier == .iteratedAndSalted {
            guard iterationsCount > 0 else {
                throw PGPError.general
        }
            data.append(UInt8(iterationsCount))
        }
        
        return data
    }
    
    // MARK: - NSCopying
    
    public func copy(with zone: NSZone? = nil) -> Any {
        let copy = PGPS2K(specifier: specifier, hashAlgorithm: hashAlgorithm)
        copy.salt = salt
        copy.iterationsCount = iterationsCount
        return copy
    }
}

// MARK: - Data Extensions for Additional Hashes

// Hash methods are now in PGPFoundation.swift extension
