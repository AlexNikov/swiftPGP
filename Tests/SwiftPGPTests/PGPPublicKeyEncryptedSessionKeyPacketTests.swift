//
//  PGPPublicKeyEncryptedSessionKeyPacketTests.swift
//  SwiftPGPTests
//

import XCTest
import SwiftPGP

class PGPPublicKeyEncryptedSessionKeyPacketTests: XCTestCase {
    
    func testPacketCreation() {
        let packet = PGPPublicKeyEncryptedSessionKeyPacket()
        XCTAssertEqual(packet.version, 3)
        XCTAssertEqual(packet.tag, .publicKeyEncryptedSessionKey)
        XCTAssertEqual(packet.publicKeyAlgorithm, .rsa)
    }
    
    func testPacketParsing() throws {
        // Create a minimal packet structure for testing
        var data = Data()
        data.append(3) // Version
        data.append(Data(repeating: 0, count: 8)) // Key ID (8 bytes)
        data.append(PGPPublicKeyAlgorithm.rsa.rawValue) // Algorithm
        
        // Add a minimal MPI (2 bytes length + 1 byte data)
        var mpiLength: UInt16 = 8 // 8 bits = 1 byte
        mpiLength = mpiLength.bigEndian
        data.append(Data(bytes: &mpiLength, count: 2))
        data.append(Data([0x01])) // MPI data
        
        let packet = PGPPublicKeyEncryptedSessionKeyPacket()
        XCTAssertNoThrow(try packet.parse(data: data))
        
        XCTAssertEqual(packet.version, 3)
        XCTAssertNotNil(packet.keyID)
        XCTAssertEqual(packet.publicKeyAlgorithm, .rsa)
        XCTAssertEqual(packet.encryptedMPIs.count, 1)
    }
    
    func testPacketExport() throws {
        let packet = PGPPublicKeyEncryptedSessionKeyPacket()
        packet.version = 3
        packet.publicKeyAlgorithm = .rsa
        
        // Create a dummy key ID
        let keyIDData = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        packet.keyID = PGPKeyID(longKey: keyIDData)
        
        // Add a dummy encrypted MPI
        let encryptedData = Data([0x01, 0x02, 0x03, 0x04])
        let mpi = PGPMPI(bigNum: PGPBigNum(data: encryptedData), identifier: PGPMPIdentifier.m)
        packet.encryptedMPIs = [mpi]
        
        let exported = try packet.export()
        XCTAssertFalse(exported.isEmpty)
        
        // Verify it can be parsed back
        guard let (bodyData, tag, _, _) = PGPPacket.readPacketBody(from: exported) else {
            XCTFail("Failed to read packet body")
            return
        }
        
        XCTAssertEqual(tag, .publicKeyEncryptedSessionKey)
        
        let parsedPacket = PGPPublicKeyEncryptedSessionKeyPacket()
        XCTAssertNoThrow(try parsedPacket.parse(data: bodyData))
        
        XCTAssertEqual(parsedPacket.version, 3)
        XCTAssertEqual(parsedPacket.publicKeyAlgorithm, .rsa)
    }
    
    func testPacketWithElgamalAlgorithm() throws {
        var data = Data()
        data.append(3) // Version
        data.append(Data(repeating: 0, count: 8)) // Key ID
        data.append(PGPPublicKeyAlgorithm.elgamal.rawValue) // Algorithm
        
        // Add two MPIs for Elgamal
        var mpiLength1: UInt16 = 8
        mpiLength1 = mpiLength1.bigEndian
        data.append(Data(bytes: &mpiLength1, count: 2))
        data.append(Data([0x01]))
        
        var mpiLength2: UInt16 = 8
        mpiLength2 = mpiLength2.bigEndian
        data.append(Data(bytes: &mpiLength2, count: 2))
        data.append(Data([0x02]))
        
        let packet = PGPPublicKeyEncryptedSessionKeyPacket()
        XCTAssertNoThrow(try packet.parse(data: data))
        
        XCTAssertEqual(packet.publicKeyAlgorithm, .elgamal)
        XCTAssertEqual(packet.encryptedMPIs.count, 2)
    }
}

