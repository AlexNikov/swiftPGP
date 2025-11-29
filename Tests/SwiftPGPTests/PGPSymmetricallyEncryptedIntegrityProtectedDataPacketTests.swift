//
//  PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTests.swift
//  SwiftPGPTests
//

import XCTest
import SwiftPGP

class PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTests: XCTestCase {
    
    func testPacketCreation() {
        let packet = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        XCTAssertEqual(packet.version, 1)
        XCTAssertEqual(packet.tag, .symmetricallyEncryptedIntegrityProtectedData)
    }
    
    func testPacketParsing() throws {
        var data = Data()
        data.append(1) // Version
        data.append(Data([0x01, 0x02, 0x03, 0x04, 0x05])) // Encrypted data
        
        let packet = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        XCTAssertNoThrow(try packet.parse(data: data))
        
        XCTAssertEqual(packet.version, 1)
        XCTAssertNotNil(packet.encryptedData)
        XCTAssertEqual(packet.encryptedData?.count, 5)
    }
    
    func testPacketExport() throws {
        let packet = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        packet.encryptedData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        
        let exported = try packet.export()
        XCTAssertFalse(exported.isEmpty)
        
        // Verify it can be parsed back
        guard let (bodyData, tag, _, _) = PGPPacket.readPacketBody(from: exported) else {
            XCTFail("Failed to read packet body")
            return
        }
        
        XCTAssertEqual(tag, .symmetricallyEncryptedIntegrityProtectedData)
        
        let parsedPacket = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        XCTAssertNoThrow(try parsedPacket.parse(data: bodyData))
        
        XCTAssertEqual(parsedPacket.version, 1)
        XCTAssertEqual(parsedPacket.encryptedData, Data([0x01, 0x02, 0x03, 0x04, 0x05]))
    }
    
    func testEncryptDecryptRoundTrip() throws {
        // This test requires RSA operations to be implemented
        // For now, we'll just test the structure
        
        let originalData = "Hello, PGP!".data(using: .utf8)!
        let sessionKey = PGPCryptoUtils.randomData(length: 32) // AES256 key
        let algorithm: PGPSymmetricAlgorithm = .aes256
        
        let packet = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        
        // Encrypt
        XCTAssertNoThrow(try packet.encrypt(literalPacketData: originalData,
                                           symmetricAlgorithm: algorithm,
                                           sessionKeyData: sessionKey))
        
        XCTAssertNotNil(packet.encryptedData)
        XCTAssertGreaterThan(packet.encryptedData?.count ?? 0, originalData.count)
        
        // Decrypt
        let decryptedPackets = try packet.decrypt(symmetricAlgorithm: algorithm,
                                                 sessionKeyData: sessionKey)
        
        // Should contain at least one packet
        XCTAssertFalse(decryptedPackets.isEmpty)
        
        // Find literal packet
        if let literalPacket = decryptedPackets.first(where: { $0.tag == .literalData }) as? PGPLiteralPacket {
            XCTAssertEqual(literalPacket.literalRawData, originalData)
        }
    }
    
    func testEmptyDataHandling() {
        let packet = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
        
        // Parsing empty data should throw
        XCTAssertThrowsError(try packet.parse(data: Data())) { error in
            XCTAssertTrue(error is PGPError)
        }
    }
}

