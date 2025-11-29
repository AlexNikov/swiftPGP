//
//  PGPArmorTests.swift
//  SwiftPGPTests
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

import XCTest
@testable import SwiftPGP

final class PGPArmorTests: XCTestCase {
    
    func testArmorPublicKey() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(data, as: .publicKey)
        
        print("Armored Output:\n\(armored)")
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        XCTAssertTrue(armored.contains("-----END PGP PUBLIC KEY BLOCK-----"))
        XCTAssertTrue(armored.contains("AQIDBAU=")) // Base64 of test data
        
        // Calculate expected CRC manually to verify
        let crc24 = data.pgpCRC24
        let crcBytes = [
            UInt8((crc24 >> 16) & 0xFF),
            UInt8((crc24 >> 8) & 0xFF),
            UInt8(crc24 & 0xFF)
        ]
        let expectedChecksum = Data(crcBytes).base64EncodedString()
        print("Expected Checksum: =\(expectedChecksum)")
        
        XCTAssertTrue(armored.contains("=\(expectedChecksum)")) 
    }
    
    func testReadArmored() throws {
        let originalData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(originalData, as: .publicKey)
        
        let decoded = try PGPArmor.readArmored(armored)
        XCTAssertEqual(decoded, originalData)
    }
    
    func testReadArmoredWithInvalidChecksum() {
        let originalData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        var armored = PGPArmor.armored(originalData, as: .publicKey)
        
        // Calculate valid checksum
        let crc24 = originalData.pgpCRC24
        let crcBytes = [
            UInt8((crc24 >> 16) & 0xFF),
            UInt8((crc24 >> 8) & 0xFF),
            UInt8(crc24 & 0xFF)
        ]
        let validChecksum = "=" + Data(crcBytes).base64EncodedString()
        
        // Replace with invalid checksum (but valid Base64)
        // AAAAAA== decodes to [0, 0, 0, 0], we need 3 bytes
        // AAAA decodes to [0, 0, 0] (roughly)
        let invalidChecksum = "=AAAA" 
        
        // Ensure we actually replaced something
        guard armored.contains(validChecksum) else {
            XCTFail("Could not find valid checksum \(validChecksum) in armored string")
            return
        }
        
        armored = armored.replacingOccurrences(of: validChecksum, with: invalidChecksum)
        
        XCTAssertThrowsError(try PGPArmor.readArmored(armored)) { error in
            XCTAssertEqual(error as? PGPError, PGPError.invalidMessage)
        }
    }
    
    func testArmorMessage() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let armored = PGPArmor.armored(data, as: .message)
        
        XCTAssertTrue(armored.contains("-----BEGIN PGP MESSAGE-----"))
        XCTAssertTrue(armored.contains("-----END PGP MESSAGE-----"))
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
}
