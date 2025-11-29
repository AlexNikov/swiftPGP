//
//  PGPCryptoCFBTests.swift
//  SwiftPGPTests
//

import XCTest
@testable import SwiftPGP

final class PGPCryptoCFBTests: XCTestCase {
    
    func testAESCFBEncryptDecrypt() {
        let plaintext = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        let key = Data([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]) // AES-128 key
        let iv = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        // Encrypt
        guard let encrypted = PGPCryptoCFB.encryptData(plaintext,
                                                       sessionKeyData: key,
                                                       symmetricAlgorithm: .aes128,
                                                       iv: iv,
                                                       syncCFB: false) else {
            XCTFail("Encryption failed")
            return
        }
        
        // Decrypt
        guard let decrypted = PGPCryptoCFB.decryptData(encrypted,
                                                      sessionKeyData: key,
                                                      symmetricAlgorithm: .aes128,
                                                      iv: iv,
                                                      syncCFB: false) else {
            XCTFail("Decryption failed")
            return
        }
        
        XCTAssertEqual(decrypted, plaintext)
    }
    
    func testAESCFBWithDifferentSizes() {
        let plaintext = Data([0x01, 0x02, 0x03, 0x04, 0x05]) // 5 bytes (not multiple of 16)
        let key = Data([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
        let iv = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        guard let encrypted = PGPCryptoCFB.encryptData(plaintext,
                                                       sessionKeyData: key,
                                                       symmetricAlgorithm: .aes128,
                                                       iv: iv,
                                                       syncCFB: false) else {
            XCTFail("Encryption failed")
            return
        }
        
        guard let decrypted = PGPCryptoCFB.decryptData(encrypted,
                                                      sessionKeyData: key,
                                                      symmetricAlgorithm: .aes128,
                                                      iv: iv,
                                                      syncCFB: false) else {
            XCTFail("Decryption failed")
            return
        }
        
        XCTAssertEqual(decrypted, plaintext)
    }
}

