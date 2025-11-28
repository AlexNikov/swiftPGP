//  PGPFingerprintTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPFingerprintTests: XCTestCase {
    
    func testFingerprintCreation() {
        let fingerprintData = Data([
            0x81, 0x6E, 0x6A, 0x80, 0x80, 0x67, 0xD4, 0x1E,
            0x4C, 0xB0, 0x3F, 0xCC, 0x94, 0x69, 0x00, 0x93,
            0xAE, 0xEF, 0x64, 0xC8
        ])
        
        let fingerprint = PGPFingerprint(fingerprintData: fingerprintData)
        XCTAssertEqual(fingerprint.fingerprintData, fingerprintData)
        XCTAssertEqual(fingerprint.hexString, "816E6A808067D41E4CB03FCC94690093AEEF64C8")
    }
    
    func testFingerprintEquality() {
        let data1 = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let data2 = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let data3 = Data([0x01, 0x02, 0x03, 0x04, 0x06])
        
        let fp1 = PGPFingerprint(fingerprintData: data1)
        let fp2 = PGPFingerprint(fingerprintData: data2)
        let fp3 = PGPFingerprint(fingerprintData: data3)
        
        XCTAssertEqual(fp1, fp2)
        XCTAssertNotEqual(fp1, fp3)
    }
    
    func testFingerprintCopy() {
        let fingerprintData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let fingerprint = PGPFingerprint(fingerprintData: fingerprintData)
        
        let copied = fingerprint.copy() as? PGPFingerprint
        XCTAssertNotNil(copied)
        XCTAssertEqual(fingerprint, copied)
        XCTAssertFalse(fingerprint === copied, "Copy should create a new instance")
    }
}

