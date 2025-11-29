//
//  PGPCryptoUtilsTests.swift
//  SwiftPGPTests
//

import XCTest
import SwiftPGP

class PGPCryptoUtilsTests: XCTestCase {
    
    func testRandomDataGeneration() {
        let data1 = PGPCryptoUtils.randomData(length: 16)
        let data2 = PGPCryptoUtils.randomData(length: 16)
        
        XCTAssertEqual(data1.count, 16)
        XCTAssertEqual(data2.count, 16)
        // Very unlikely to be the same
        XCTAssertNotEqual(data1, data2)
    }
    
    func testRandomDataDifferentLengths() {
        let data8 = PGPCryptoUtils.randomData(length: 8)
        let data16 = PGPCryptoUtils.randomData(length: 16)
        let data32 = PGPCryptoUtils.randomData(length: 32)
        
        XCTAssertEqual(data8.count, 8)
        XCTAssertEqual(data16.count, 16)
        XCTAssertEqual(data32.count, 32)
    }
    
    func testKeySizeOfSymmetricAlgorithm() {
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.aes128), 16)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.aes192), 24)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.aes256), 32)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.tripleDES), 24)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.cast5), 16)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.blowfish), 16)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.twofish256), 32)
        XCTAssertEqual(PGPCryptoUtils.keySizeOfSymmetricAlgorithm(.plaintext), 0)
    }
    
    func testBlockSizeOfSymmetricAlgorithm() {
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.aes128), 16)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.aes192), 16)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.aes256), 16)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.tripleDES), 8)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.cast5), 8)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.blowfish), 8)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.twofish256), 16)
        XCTAssertEqual(PGPCryptoUtils.blockSizeOfSymmetricAlgorithm(.plaintext), 0)
    }
}

