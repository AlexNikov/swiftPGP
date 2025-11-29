//
//  PGPCryptoCFB.swift
//  SwiftPGP
//

import Foundation
import CommonCrypto

/// CFB (Cipher Feedback) mode encryption/decryption for PGP
public class PGPCryptoCFB {
    
    /// Decrypt data using CFB mode
    public static func decryptData(_ encryptedData: Data,
                                   sessionKeyData: Data,
                                   symmetricAlgorithm: PGPSymmetricAlgorithm,
                                   iv: Data,
                                   syncCFB: Bool = false) -> Data? {
        return manipulateData(encryptedData,
                             sessionKeyData: sessionKeyData,
                             symmetricAlgorithm: symmetricAlgorithm,
                             iv: iv,
                             syncCFB: syncCFB,
                             decrypt: true)
    }
    
    /// Encrypt data using CFB mode
    public static func encryptData(_ data: Data,
                                   sessionKeyData: Data,
                                   symmetricAlgorithm: PGPSymmetricAlgorithm,
                                   iv: Data,
                                   syncCFB: Bool = false) -> Data? {
        return manipulateData(data,
                             sessionKeyData: sessionKeyData,
                             symmetricAlgorithm: symmetricAlgorithm,
                             iv: iv,
                             syncCFB: syncCFB,
                             decrypt: false)
    }
    
    // MARK: - Private
    
    private static func manipulateData(_ data: Data,
                                      sessionKeyData: Data,
                                      symmetricAlgorithm: PGPSymmetricAlgorithm,
                                      iv: Data,
                                      syncCFB: Bool,
                                      decrypt: Bool) -> Data? {
        guard !sessionKeyData.isEmpty, !data.isEmpty, !iv.isEmpty else {
            return nil
        }
        
        let keySize = keySizeOfSymmetricAlgorithm(symmetricAlgorithm)
        let blockSize = blockSizeOfSymmetricAlgorithm(symmetricAlgorithm)
        
        guard keySize > 0, blockSize > 0, sessionKeyData.count >= keySize else {
            return nil
        }
        
        // Extract key
        let key = sessionKeyData.prefix(keySize)
        
        switch symmetricAlgorithm {
        case .aes128, .aes192, .aes256:
            return aesCFB(data: data, key: key, iv: iv, blockSize: blockSize, syncCFB: syncCFB, decrypt: decrypt)
            
        case .cast5:
            // CAST5 requires OpenSSL or custom implementation
            // For now, return nil - can be implemented later
            return nil
            
        case .blowfish:
            // Blowfish requires OpenSSL or custom implementation
            return nil
            
        case .tripleDES:
            // 3DES requires OpenSSL or custom implementation
            return nil
            
        case .idea:
            // IDEA requires OpenSSL or custom implementation
            return nil
            
        case .twofish256:
            // Twofish requires custom implementation
            return nil
            
        case .plaintext:
            return data
            
        case .max:
            return nil
        }
    }
    
    // MARK: - AES CFB
    
    private static func getCCAlgorithm(for keySize: Int) -> CCAlgorithm {
        switch keySize {
        case 16: return CCAlgorithm(kCCAlgorithmAES128)
        case 24: return CCAlgorithm(kCCAlgorithmAES)
        case 32: return CCAlgorithm(kCCAlgorithmAES)
        default: return CCAlgorithm(kCCAlgorithmAES)
        }
    }
    
    private static func aesCFB(data: Data, key: Data, iv: Data, blockSize: Int, syncCFB: Bool, decrypt: Bool) -> Data? {
        if syncCFB {
            // OpenPGP-specific CFB mode (RFC 4880 section 13.9)
            return openPGP_CFB_decrypt(data: data, blockSize: blockSize, iv: iv) { inputData in
                return aesEncryptECB(data: inputData, key: key)
            }
        } else {
            // Standard CFB mode using CommonCrypto
            return aesCFB128(data: data, key: key, iv: iv, decrypt: decrypt)
        }
    }
    
    private static func aesCFB128(data: Data, key: Data, iv: Data, decrypt: Bool) -> Data? {
        // CommonCrypto doesn't support CFB directly, use manual implementation
        return aesCFBManual(data: data, key: key, iv: iv, decrypt: decrypt)
    }
    
    private static func aesCFBManual(data: Data, key: Data, iv: Data, decrypt: Bool) -> Data? {
        // Manual CFB implementation
        var feedback = iv
        var output = Data()
        
        let blockSize = 16 // AES block size
        
        for i in stride(from: 0, to: data.count, by: blockSize) {
            let chunkSize = min(blockSize, data.count - i)
            let chunk = data.subdata(in: i..<i+chunkSize)
            
            // Encrypt feedback register
            guard let encryptedFeedback = aesEncryptECB(data: feedback, key: key) else {
                return nil
            }
            
            // XOR with chunk
            let result = xorData(encryptedFeedback.prefix(chunkSize), chunk)
            output.append(result)
            
            // Update feedback register
            if decrypt {
                feedback = chunk // Use ciphertext for next block
            } else {
                feedback = result // Use plaintext for next block
            }
        }
        
        return output
    }
    
    private static func aesEncryptECB(data: Data, key: Data) -> Data? {
        let algorithm = getCCAlgorithm(for: key.count)
        
        // ECB mode requires data to be multiple of block size
        let blockSize = 16
        let paddedLength = ((data.count + blockSize - 1) / blockSize) * blockSize
        var paddedData = data
        if paddedData.count < paddedLength {
            paddedData.append(Data(repeating: 0, count: paddedLength - paddedData.count))
        }
        
        // Copy to arrays to avoid conflicting access
        let keyArray = Array(key)
        let dataArray = Array(paddedData)
        var outputArray = [UInt8](repeating: 0, count: paddedLength)
        var dataOutMoved: size_t = 0
        
        let status = keyArray.withUnsafeBufferPointer { keyBuffer in
            dataArray.withUnsafeBufferPointer { dataBuffer in
                outputArray.withUnsafeMutableBufferPointer { outputBuffer in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        algorithm,
                        CCOptions(kCCOptionECBMode),
                        keyBuffer.baseAddress, key.count,
                        nil, // No IV for ECB
                        dataBuffer.baseAddress, paddedLength,
                        outputBuffer.baseAddress, paddedLength,
                        &dataOutMoved
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            return nil
        }
        
        let outputData = Data(outputArray.prefix(Int(dataOutMoved)))
        // Return only the part that corresponds to original data length
        return outputData.prefix(data.count)
    }
    
    // MARK: - OpenPGP CFB (RFC 4880 section 13.9)
    
    /// OpenPGP-specific CFB mode with resync
    private static func openPGP_CFB_decrypt(data: Data,
                                           blockSize: Int,
                                           iv: Data,
                                           cipherEncrypt: (Data) -> Data?) -> Data? {
        let BS = blockSize
        
        // 1. The feedback register (FR) is set to the IV
        var FR = iv
        
        // 2. FR is encrypted to produce FRE (FR Encrypted)
        guard var FRE = cipherEncrypt(FR) else {
            return nil
        }
        
        // 4. FR is loaded with C[1] through C[BS]
        guard data.count >= BS else {
            return nil
        }
        FR = data.subdata(in: 0..<BS)
        
        // 3. FRE is xored with the first BS octets to produce prefix
        let prefix = xorData(FRE.prefix(BS), FR)
        
        // 5. FR is encrypted to produce FRE
        guard let newFRE = cipherEncrypt(FR) else {
            return nil
        }
        FRE = newFRE
        
        // 6. Check value verification
        guard data.count >= BS + 2 else {
            return nil
        }
        let checkValue = data.subdata(in: BS..<BS+2)
        let expectedCheck = xorData(FRE.prefix(2), checkValue)
        let prefixCheck = prefix.subdata(in: BS-2..<BS)
        
        guard expectedCheck == prefixCheck else {
            // Bad OpenPGP CFB check value
            return nil
        }
        
        // Decrypt the rest
        var plaintext = Data()
        var x = BS + 2
        
        while x + BS <= data.count {
            let chunk = data.subdata(in: x..<x+BS)
            let decryptedChunk = xorData(FRE, chunk)
            plaintext.append(decryptedChunk)
            
            // Update FRE for next iteration
            guard let nextFRE = cipherEncrypt(chunk) else {
                return nil
            }
            FRE = nextFRE
            x += BS
        }
        
        // Last partial block
        if x < data.count {
            let remaining = data.subdata(in: x..<data.count)
            let decryptedRemaining = xorData(FRE.prefix(remaining.count), remaining)
            plaintext.append(decryptedRemaining)
        }
        
        // Remove prefix from plaintext (first BS bytes are random prefix)
        guard plaintext.count >= BS else {
            return nil
        }
        let actualPlaintext = plaintext.subdata(in: BS..<plaintext.count)
        
        // Reconstruct: prefix + check + plaintext
        var result = prefix
        result.append(prefix.subdata(in: BS-2..<BS)) // Check value
        result.append(actualPlaintext)
        
        return result
    }
    
    // MARK: - Helper Functions
    
    private static func xorData(_ data1: Data, _ data2: Data) -> Data {
        let minLength = min(data1.count, data2.count)
        var result = Data(count: minLength)
        
        for i in 0..<minLength {
            result[i] = data1[i] ^ data2[i]
        }
        
        return result
    }
    
    private static func keySizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        case .cast5: return 16
        case .blowfish: return 16
        case .tripleDES: return 24
        case .idea: return 16
        case .twofish256: return 32
        case .plaintext: return 0
        default: return 16
        }
    }
    
    private static func blockSizeOfSymmetricAlgorithm(_ algorithm: PGPSymmetricAlgorithm) -> Int {
        switch algorithm {
        case .aes128, .aes192, .aes256: return 16
        case .cast5, .blowfish, .idea, .tripleDES: return 8
        case .twofish256: return 16
        case .plaintext: return 0
        default: return 16
        }
    }
}

