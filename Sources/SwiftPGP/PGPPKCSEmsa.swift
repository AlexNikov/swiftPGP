//
//  PGPPKCSEmsa.swift
//  SwiftPGP
//

import Foundation
import CommonCrypto

/// PKCS EMSA-PKCS1-v1_5 padding for RSA signatures
/// See RFC 4880 section 13.1.3
public class PGPPKCSEmsa {
    
    // ASN.1 prefixes for different hash algorithms
    private static let prefixMD5: [UInt8] = [0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10]
    private static let prefixSHA1: [UInt8] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]
    private static let prefixSHA224: [UInt8] = [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C]
    private static let prefixSHA256: [UInt8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
    private static let prefixSHA384: [UInt8] = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
    private static let prefixSHA512: [UInt8] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
    private static let prefixRIPEMD160: [UInt8] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14]
    
    /// Create EMSA-PKCS1-v1_5 padding
    /// - Parameters:
    ///   - hashAlgorithm: Hash algorithm to use
    ///   - message: Message to be encoded
    ///   - encodedMessageLength: Intended length in octets of the encoded message
    /// - Returns: Encoded message with PKCS padding
    public static func encode(hashAlgorithm: PGPHashAlgorithm, message: Data, encodedMessageLength: Int) throws -> Data {
        // Build T = prefix || hash(M)
        var tData = Data()
        
        let hashData: Data
        let prefix: [UInt8]
        
        switch hashAlgorithm {
        case .md5:
            prefix = prefixMD5
            hashData = message.pgpMD5
        case .sha1:
            prefix = prefixSHA1
            hashData = message.pgpSHA1
        case .sha224:
            prefix = prefixSHA224
            hashData = message.pgpSHA224
        case .sha256:
            prefix = prefixSHA256
            hashData = message.pgpSHA256
        case .sha384:
            prefix = prefixSHA384
            hashData = message.pgpSHA384
        case .sha512:
            prefix = prefixSHA512
            hashData = message.pgpSHA512
        case .ripemd160:
            prefix = prefixRIPEMD160
            hashData = message.pgpRIPEMD160
        default:
            throw PGPError.general
        }
        
        tData.append(Data(prefix))
        tData.append(hashData)
        
        let tLen = tData.count
        
        // Check length requirement
        if encodedMessageLength < tLen + 11 {
            throw PGPError.general
        }
        
        // Generate PS (padding string) of 0xFF bytes
        let psLength = encodedMessageLength - tLen - 3
        var psData = Data(repeating: 0xFF, count: psLength)
        
        // Build EM = 0x00 || 0x01 || PS || 0x00 || T
        var emData = Data()
        emData.append(0x00)
        emData.append(0x01)
        emData.append(psData)
        emData.append(0x00)
        emData.append(tData)
        
        return emData
    }
}

