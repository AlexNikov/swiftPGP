//
//  PGPS2KTests.swift
//  SwiftPGPTests
//

import XCTest
@testable import SwiftPGP

final class PGPS2KTests: XCTestCase {
    
    func testSimpleS2K() {
        let s2k = PGPS2K(specifier: .simple, hashAlgorithm: .sha1)
        let passphrase = "test"
        
        guard let key = s2k.produceSessionKey(passphrase: passphrase, symmetricAlgorithm: .aes128) else {
            XCTFail("Failed to produce session key")
            return
        }
        
        XCTAssertEqual(key.count, 16) // AES-128 requires 16 bytes
    }
    
    func testSaltedS2K() {
        let s2k = PGPS2K(specifier: .salted, hashAlgorithm: .sha1)
        s2k.salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let passphrase = "test"
        
        guard let key = s2k.produceSessionKey(passphrase: passphrase, symmetricAlgorithm: .aes128) else {
            XCTFail("Failed to produce session key")
            return
        }
        
        XCTAssertEqual(key.count, 16)
    }
    
    func testS2KParsing() {
        // Simple S2K: specifier (0) + hash (2 = SHA1)
        let data = Data([0x00, 0x02])
        
        guard let (s2k, length) = PGPS2K.s2k(from: data, at: 0) else {
            XCTFail("Failed to parse S2K")
            return
        }
        
        XCTAssertEqual(s2k.specifier, .simple)
        XCTAssertEqual(s2k.hashAlgorithm, .sha1)
        XCTAssertEqual(length, 2)
    }
    
    func testS2KExport() {
        let s2k = PGPS2K(specifier: .simple, hashAlgorithm: .sha1)
        
        do {
            let exported = try s2k.export()
            XCTAssertEqual(exported.count, 2) // specifier + hash
            XCTAssertEqual(exported[0], 0x00) // Simple
            XCTAssertEqual(exported[1], 0x02) // SHA1
        } catch {
            XCTFail("Export failed: \(error)")
        }
    }
}

