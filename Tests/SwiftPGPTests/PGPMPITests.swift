//
//  PGPMPITests.swift
//  SwiftPGPTests
//

import XCTest
@testable import SwiftPGP

final class PGPMPITests: XCTestCase {
    
    func testMPICreationFromData() {
        let data = Data([0x01, 0x02, 0x03])
        let mpi = PGPMPI(data: data, identifier: PGPMPIdentifier.n)
        
        XCTAssertEqual(mpi.identifier, PGPMPIdentifier.n)
        XCTAssertEqual(mpi.bodyData(), data)
    }
    
    func testMPIParsing() {
        // Create MPI manually: 2 bytes (bit count) + number bytes
        // For 24 bits (3 bytes): 0x00 0x18 (24 in big-endian) + 0x01 0x02 0x03
        var mpiData = Data()
        var bits: UInt16 = 24
        var bitsBE = bits.bigEndian
        mpiData.append(Data(bytes: &bitsBE, count: 2))
        mpiData.append(Data([0x01, 0x02, 0x03]))
        
        guard let mpi = PGPMPI(mpiData: mpiData, identifier: PGPMPIdentifier.e, at: 0) else {
            XCTFail("Failed to parse MPI")
            return
        }
        
        XCTAssertEqual(mpi.identifier, PGPMPIdentifier.e)
        XCTAssertEqual(mpi.packetLength, 5) // 2 bytes header + 3 bytes data
        XCTAssertEqual(mpi.bodyData(), Data([0x01, 0x02, 0x03]))
    }
    
    func testMPIExport() {
        let data = Data([0x01, 0x02, 0x03])
        let mpi = PGPMPI(data: data, identifier: PGPMPIdentifier.n)
        
        let exported = mpi.exportMPI()
        
        // Should have 2-byte header + 3-byte body
        XCTAssertEqual(exported.count, 5)
        
        // Parse it back
        guard let parsed = PGPMPI(mpiData: exported, identifier: PGPMPIdentifier.n, at: 0) else {
            XCTFail("Failed to parse exported MPI")
            return
        }
        
        XCTAssertEqual(parsed.bodyData(), data)
    }
    
    func testMPIWithLeadingZeros() {
        // Test that leading zeros are handled correctly
        let data = Data([0x00, 0x00, 0x01, 0x02])
        let mpi = PGPMPI(data: data, identifier: PGPMPIdentifier.n)
        
        // Leading zeros should be removed
        let body = mpi.bodyData()
        XCTAssertEqual(body, Data([0x01, 0x02]))
    }
    
    func testMPIEquality() {
        let data1 = Data([0x01, 0x02, 0x03])
        let mpi1 = PGPMPI(data: data1, identifier: PGPMPIdentifier.n)
        
        let data2 = Data([0x01, 0x02, 0x03])
        let mpi2 = PGPMPI(data: data2, identifier: PGPMPIdentifier.n)
        
        XCTAssertEqual(mpi1, mpi2)
    }
    
    func testMPICopy() {
        let data = Data([0x01, 0x02, 0x03])
        let mpi = PGPMPI(data: data, identifier: PGPMPIdentifier.n)
        
        let copy = mpi.copy() as! PGPMPI
        
        XCTAssertEqual(mpi.identifier, copy.identifier)
        XCTAssertEqual(mpi.bodyData(), copy.bodyData())
    }
}

final class PGPBigNumTests: XCTestCase {
    
    func testBigNumCreation() {
        let data = Data([0x01, 0x02, 0x03])
        let bigNum = PGPBigNum(data: data)
        
        XCTAssertEqual(bigNum.bigEndianData, data)
    }
    
    func testBigNumBitsCount() {
        // 0x01 = 1 bit
        let data1 = Data([0x01])
        let bigNum1 = PGPBigNum(data: data1)
        XCTAssertEqual(bigNum1.bitsCount, 1)
        
        // 0x80 = 8 bits
        let data2 = Data([0x80])
        let bigNum2 = PGPBigNum(data: data2)
        XCTAssertEqual(bigNum2.bitsCount, 8)
        
        // 0xFF = 8 bits
        let data3 = Data([0xFF])
        let bigNum3 = PGPBigNum(data: data3)
        XCTAssertEqual(bigNum3.bitsCount, 8)
    }
    
    func testBigNumBytesCount() {
        let data = Data([0x00, 0x00, 0x01, 0x02])
        let bigNum = PGPBigNum(data: data)
        
        // Should count only non-zero bytes
        XCTAssertEqual(bigNum.bytesCount, 2)
    }
    
    func testBigNumWithLeadingZeros() {
        let data = Data([0x00, 0x00, 0x01, 0x02])
        let bigNum = PGPBigNum(data: data)
        
        // Leading zeros should be removed
        XCTAssertEqual(bigNum.bigEndianData, Data([0x01, 0x02]))
    }
    
    func testBigNumFromHexString() {
        guard let bigNum = PGPBigNum(hexString: "010203") else {
            XCTFail("Failed to create BigNum from hex string")
            return
        }
        
        XCTAssertEqual(bigNum.bigEndianData, Data([0x01, 0x02, 0x03]))
    }
    
    func testBigNumEquality() {
        let data1 = Data([0x01, 0x02, 0x03])
        let bigNum1 = PGPBigNum(data: data1)
        
        let data2 = Data([0x01, 0x02, 0x03])
        let bigNum2 = PGPBigNum(data: data2)
        
        XCTAssertEqual(bigNum1, bigNum2)
    }
}

