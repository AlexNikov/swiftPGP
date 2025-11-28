//  PGPArmorTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPArmorTests: XCTestCase {
    
    func testArmorPublicKey() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(data, as: .publicKey)
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        XCTAssertTrue(armored.contains("-----END PGP PUBLIC KEY BLOCK-----"))
        XCTAssertTrue(armored.contains("AQIDBAU=")) // Base64 of test data
    }
    
    func testArmorSecretKey() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(data, as: .secretKey)
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        XCTAssertTrue(armored.contains("-----END PGP PRIVATE KEY BLOCK-----"))
    }
    
    func testArmorMessage() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(data, as: .message)
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP MESSAGE-----"))
        XCTAssertTrue(armored.contains("-----END PGP MESSAGE-----"))
    }
    
    func testArmorSignature() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(data, as: .signature)
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP SIGNATURE-----"))
        XCTAssertTrue(armored.contains("-----END PGP SIGNATURE-----"))
    }
    
    func testReadArmored() throws {
        let originalData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(originalData, as: .publicKey)
        
        let decoded = try PGPArmor.readArmored(armored)
        XCTAssertEqual(decoded, originalData)
    }
    
    func testIsArmoredData() {
        let data = Data([0x01, 0x02, 0x03])
        XCTAssertFalse(PGPArmor.isArmoredData(data))
        
        let armored = PGPArmor.armored(data, as: .message)
        let armoredData = armored.data(using: .utf8)!
        XCTAssertTrue(PGPArmor.isArmoredData(armoredData))
    }
    
    func testConvertArmoredMessage2BinaryBlocksWhenNecessary() throws {
        // Test with binary data
        let binaryData = Data([0x01, 0x02, 0x03])
        let blocks = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(binaryData)
        XCTAssertEqual(blocks.count, 1)
        XCTAssertEqual(blocks[0], binaryData)
        
        // Test with armored data
        let armored = PGPArmor.armored(binaryData, as: .message)
        let armoredData = armored.data(using: .utf8)!
        let decodedBlocks = try PGPArmor.convertArmoredMessage2BinaryBlocksWhenNecessary(armoredData)
        XCTAssertEqual(decodedBlocks.count, 1)
        XCTAssertEqual(decodedBlocks[0], binaryData)
    }
    
    func testArmorMultipart() {
        let data = Data([0x01, 0x02, 0x03])
        let armored = PGPArmor.armored(data, as: .multipartMessagePartXOfY, part: 1, of: 3)
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP MESSAGE, PART 1/3-----"))
        XCTAssertTrue(armored.contains("-----END PGP MESSAGE, PART 1/3-----"))
    }
}

