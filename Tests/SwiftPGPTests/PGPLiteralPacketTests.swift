//
//  PGPLiteralPacketTests.swift
//  SwiftPGPTests
//

import XCTest
@testable import SwiftPGP

final class PGPLiteralPacketTests: XCTestCase {
    
    func testLiteralPacketCreation() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let packet = PGPLiteralPacket.literalPacket(format: .binary, withData: data)
        
        XCTAssertEqual(packet.format, .binary)
        XCTAssertEqual(packet.literalRawData, data)
    }
    
    func testLiteralPacketParsing() {
        var body = Data()
        body.append(PGPLiteralPacketFormat.binary.rawValue) // Format
        body.append(0x00) // Filename length (0)
        var timestamp: UInt32 = 1600000000
        body.append(Data(bytes: &timestamp, count: 4)) // Timestamp
        body.append(Data([0x01, 0x02, 0x03, 0x04])) // Data
        
        let packet = PGPLiteralPacket()
        XCTAssertNoThrow(try packet.parse(data: body))
        
        XCTAssertEqual(packet.format, .binary)
        XCTAssertEqual(packet.literalRawData, Data([0x01, 0x02, 0x03, 0x04]))
    }
    
    func testLiteralPacketExport() {
        let data = Data([0x01, 0x02, 0x03])
        let packet = PGPLiteralPacket.literalPacket(format: .text, withData: data)
        packet.filename = "test.txt"
        
        guard let exported = try? packet.export() else {
            XCTFail("Export failed")
            return
        }
        
        // Parse back
        let parsedPacket = PGPLiteralPacket()
        guard let (bodyData, _, _, _) = try? PGPPacket.readPacketBody(from: exported) else {
            XCTFail("Failed to parse exported packet")
            return
        }
        XCTAssertNoThrow(try parsedPacket.parse(data: bodyData))
        
        XCTAssertEqual(parsedPacket.format, .text)
        XCTAssertEqual(parsedPacket.literalRawData, data)
    }
}

