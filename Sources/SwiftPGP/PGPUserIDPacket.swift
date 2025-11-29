//
//  PGPUserIDPacket.swift
//  SwiftPGP
//

import Foundation

public class PGPUserIDPacket: PGPPacket {
    
    public var userID: String = ""
    
    public init(userID: String) {
        self.userID = userID
        super.init(tag: .userID)
    }
    
    public init() {
        super.init(tag: .userID)
    }
    
    public override func parse(data: Data) throws {
        guard let string = String(data: data, encoding: .utf8) else {
            throw PGPError.invalidMessage
        }
        self.userID = string
    }
    
    public override func export() throws -> Data {
        guard let data = userID.data(using: .utf8) else {
            throw PGPError.general
        }
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: data.count)
        return header + data
    }
}

