//
//  PGPSignaturePacketTests.swift
//  SwiftPGPTests
//

import XCTest
@testable import SwiftPGP

final class PGPSignaturePacketTests: XCTestCase {
    
    func testSignaturePacketCreation() {
        let packet = PGPSignaturePacket.signaturePacket(type: .binaryDocument, hashAlgorithm: .sha1)
        
        XCTAssertEqual(packet.version, 4)
        XCTAssertEqual(packet.type, .binaryDocument)
        XCTAssertEqual(packet.hashAlgorithm, .sha1)
    }
    
    func testSignaturePacketParsing() {
        // Create a minimal V4 signature packet
        var body = Data()
        body.append(0x04) // Version
        body.append(PGPSignatureType.binaryDocument.rawValue) // Type
        body.append(PGPPublicKeyAlgorithm.rsa.rawValue) // Algorithm
        body.append(PGPHashAlgorithm.sha1.rawValue) // Hash
        
        // Hashed subpackets length (0)
        var hashedLength: UInt16 = 0
        body.append(Data(bytes: &hashedLength, count: 2))
        
        // Unhashed subpackets length (0)
        var unhashedLength: UInt16 = 0
        body.append(Data(bytes: &unhashedLength, count: 2))
        
        // Signed hash value (2 bytes)
        body.append(Data([0x12, 0x34]))
        
        // Signature MPI (RSA - one MPI)
        let mpiData = Data([0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]) // 8 bits = 1 byte
        body.append(mpiData)
        
        let packet = PGPSignaturePacket()
        XCTAssertNoThrow(try packet.parse(data: body))
        
        XCTAssertEqual(packet.version, 4)
        XCTAssertEqual(packet.type, .binaryDocument)
        XCTAssertEqual(packet.publicKeyAlgorithm, .rsa)
        XCTAssertEqual(packet.hashAlgorithm, .sha1)
        XCTAssertEqual(packet.signatureMPIs.count, 1)
    }
    
    func testSignatureSubpacketParsing() {
        // Create a signature creation time subpacket
        // Type (2 = signature creation time) + length (1 byte = 4) + 4-byte timestamp
        var subpacketData = Data()
        subpacketData.append(0x02) // Type
        subpacketData.append(0x04) // Length (4 bytes)
        var timestamp: UInt32 = 1600000000
        subpacketData.append(Data(bytes: &timestamp, count: 4))
        
        guard let header = PGPSignatureSubpacketHeader.from(data: subpacketData, at: 0) else {
            XCTFail("Failed to parse subpacket header")
            return
        }
        
        XCTAssertEqual(header.type, .signatureCreationTime)
        XCTAssertEqual(header.bodyLength, 4)
        
        let body = subpacketData.subdata(in: 2..<6)
        guard let subpacket = PGPSignatureSubpacket(header: header, body: body) else {
            XCTFail("Failed to parse subpacket")
            return
        }
        
        XCTAssertNotNil(subpacket.value as? Date)
    }
}

