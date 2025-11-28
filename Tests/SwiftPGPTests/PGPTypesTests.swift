//  PGPTypesTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPTypesTests: XCTestCase {
    
    func testPGPError() {
        XCTAssertEqual(PGPError.general.rawValue, -1)
        XCTAssertEqual(PGPError.passphraseRequired.rawValue, 5)
        XCTAssertEqual(PGPError.invalidSignature.rawValue, 7)
    }
    
    func testPGPPacketTag() {
        XCTAssertEqual(PGPPacketTag.publicKey.rawValue, 6)
        XCTAssertEqual(PGPPacketTag.secretKey.rawValue, 5)
        XCTAssertEqual(PGPPacketTag.signature.rawValue, 2)
        XCTAssertEqual(PGPPacketTag.literalData.rawValue, 11)
    }
    
    func testPGPPublicKeyAlgorithm() {
        XCTAssertEqual(PGPPublicKeyAlgorithm.rsa.rawValue, 1)
        XCTAssertEqual(PGPPublicKeyAlgorithm.dsa.rawValue, 17)
        XCTAssertEqual(PGPPublicKeyAlgorithm.ecdsa.rawValue, 19)
        XCTAssertEqual(PGPPublicKeyAlgorithm.edDSA.rawValue, 22)
    }
    
    func testPGPSymmetricAlgorithm() {
        XCTAssertEqual(PGPSymmetricAlgorithm.plaintext.rawValue, 0)
        XCTAssertEqual(PGPSymmetricAlgorithm.aes128.rawValue, 7)
        XCTAssertEqual(PGPSymmetricAlgorithm.aes256.rawValue, 9)
    }
    
    func testPGPHashAlgorithm() {
        XCTAssertEqual(PGPHashAlgorithm.sha1.rawValue, 2)
        XCTAssertEqual(PGPHashAlgorithm.sha256.rawValue, 8)
        XCTAssertEqual(PGPHashAlgorithm.sha512.rawValue, 10)
    }
    
    func testPGPSignatureFlags() {
        let flags: PGPSignatureFlags = [.allowSignData, .allowEncryptCommunications]
        XCTAssertTrue(flags.contains(.allowSignData))
        XCTAssertTrue(flags.contains(.allowEncryptCommunications))
        XCTAssertFalse(flags.contains(.allowCertifyOtherKeys))
    }
    
    func testPGPArmorType() {
        XCTAssertEqual(PGPArmorType.message.rawValue, 1)
        XCTAssertEqual(PGPArmorType.publicKey.rawValue, 2)
        XCTAssertEqual(PGPArmorType.secretKey.rawValue, 3)
        XCTAssertEqual(PGPArmorType.signature.rawValue, 6)
    }
}

