//  PGPKeyIDTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPKeyIDTests: XCTestCase {
    
    func testKeyIDFromLongKey() {
        // Test data: 8 bytes key ID
        let keyData = Data([0x71, 0x18, 0x0E, 0x51, 0x4E, 0xF1, 0x22, 0xE5])
        
        guard let keyID = PGPKeyID(longKey: keyData) else {
            XCTFail("Failed to create KeyID from long key")
            return
        }
        
        XCTAssertEqual(keyID.longIdentifier, "71180E514EF122E5")
        XCTAssertEqual(keyID.shortIdentifier, "4EF122E5")
    }
    
    func testKeyIDFromShortData() {
        // Test with data shorter than 8 bytes
        let shortData = Data([0x01, 0x02, 0x03])
        let keyID = PGPKeyID(longKey: shortData)
        XCTAssertNil(keyID, "KeyID should be nil for data shorter than 8 bytes")
    }
    
    func testKeyIDFromFingerprint() {
        // Test fingerprint data (20 bytes for v4)
        let fingerprintData = Data([
            0x81, 0x6E, 0x6A, 0x80, 0x80, 0x67, 0xD4, 0x1E,
            0x4C, 0xB0, 0x3F, 0xCC, 0x94, 0x69, 0x00, 0x93,
            0xAE, 0xEF, 0x64, 0xC8
        ])
        let fingerprint = PGPFingerprint(fingerprintData: fingerprintData)
        
        let keyID = PGPKeyID(fingerprint: fingerprint)
        XCTAssertEqual(keyID.longIdentifier, "94690093AEEF64C8")
        XCTAssertEqual(keyID.shortIdentifier, "AEEF64C8")
    }
    
    func testKeyIDEquality() {
        let keyData1 = Data([0x71, 0x18, 0x0E, 0x51, 0x4E, 0xF1, 0x22, 0xE5])
        let keyData2 = Data([0x71, 0x18, 0x0E, 0x51, 0x4E, 0xF1, 0x22, 0xE5])
        let keyData3 = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
        
        let keyID1 = PGPKeyID(longKey: keyData1)
        let keyID2 = PGPKeyID(longKey: keyData2)
        let keyID3 = PGPKeyID(longKey: keyData3)
        
        XCTAssertEqual(keyID1, keyID2)
        XCTAssertNotEqual(keyID1, keyID3)
    }
    
    func testKeyIDCopy() {
        let keyData = Data([0x71, 0x18, 0x0E, 0x51, 0x4E, 0xF1, 0x22, 0xE5])
        let keyID = PGPKeyID(longKey: keyData)
        
        let copied = keyID?.copy() as? PGPKeyID
        XCTAssertNotNil(copied)
        XCTAssertEqual(keyID, copied)
        XCTAssertFalse(keyID === copied, "Copy should create a new instance")
    }
}

