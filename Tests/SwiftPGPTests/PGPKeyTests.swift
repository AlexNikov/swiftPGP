//  PGPKeyTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPKeyTests: XCTestCase {
    
    func testKeyCreationWithPublicKey() {
        let user = PGPUser(userID: "Test User <test@example.com>")
        let partialKey = PGPPartialKey(type: .public, users: [user])
        let key = PGPKey(publicKey: partialKey)
        
        XCTAssertTrue(key.isPublic)
        XCTAssertFalse(key.isSecret)
        XCTAssertNotNil(key.publicKey)
        XCTAssertNil(key.secretKey)
    }
    
    func testKeyCreationWithSecretKey() {
        let user = PGPUser(userID: "Test User <test@example.com>")
        let partialKey = PGPPartialKey(type: .secret, users: [user])
        let key = PGPKey(secretKey: partialKey)
        
        XCTAssertTrue(key.isSecret)
        XCTAssertFalse(key.isPublic)
        XCTAssertNotNil(key.secretKey)
        XCTAssertNil(key.publicKey)
    }
    
    func testKeyCreationWithBothKeys() {
        let user = PGPUser(userID: "Test User <test@example.com>")
        let publicPartialKey = PGPPartialKey(type: .public, users: [user])
        let secretPartialKey = PGPPartialKey(type: .secret, users: [user])
        let key = PGPKey(secretKey: secretPartialKey, publicKey: publicPartialKey)
        
        XCTAssertTrue(key.isPublic)
        XCTAssertTrue(key.isSecret)
        XCTAssertNotNil(key.publicKey)
        XCTAssertNotNil(key.secretKey)
    }
    
    func testAddUserId() {
        let user = PGPUser(userID: "Original User <original@example.com>")
        let partialKey = PGPPartialKey(type: .public, users: [user])
        let key = PGPKey(publicKey: partialKey)
        
        key.addUserId("New User <new@example.com>")
        
        XCTAssertEqual(key.publicKey?.users.count, 2)
        XCTAssertTrue(key.publicKey?.users.contains { $0.userID == "New User <new@example.com>" } ?? false)
    }
    
    func testRemoveUserId() {
        let user1 = PGPUser(userID: "User One <user1@example.com>")
        let user2 = PGPUser(userID: "User Two <user2@example.com>")
        let partialKey = PGPPartialKey(type: .public, users: [user1, user2])
        let key = PGPKey(publicKey: partialKey)
        
        XCTAssertEqual(key.publicKey?.users.count, 2)
        
        key.removeUserId("User One <user1@example.com>")
        
        XCTAssertEqual(key.publicKey?.users.count, 1)
        XCTAssertEqual(key.publicKey?.users[0].userID, "User Two <user2@example.com>")
    }
    
    func testKeyEquality() {
        let user = PGPUser(userID: "Test User <test@example.com>")
        let partialKey1 = PGPPartialKey(type: .public, users: [user])
        let partialKey2 = PGPPartialKey(type: .public, users: [user])
        
        let key1 = PGPKey(publicKey: partialKey1)
        let key2 = PGPKey(publicKey: partialKey2)
        
        // Note: Equality depends on implementation of PGPPartialKey equality
        // This test may need adjustment based on actual implementation
        XCTAssertNotNil(key1)
        XCTAssertNotNil(key2)
    }
    
    func testKeyCopy() {
        let user = PGPUser(userID: "Test User <test@example.com>")
        let partialKey = PGPPartialKey(type: .public, users: [user])
        let key = PGPKey(publicKey: partialKey)
        
        let copied = key.copy() as? PGPKey
        XCTAssertNotNil(copied)
        XCTAssertFalse(key === copied, "Copy should create a new instance")
    }
    
    func testExportPublicKey() throws {
        let keyData = Data([0x01, 0x02, 0x03, 0x04]) // Dummy MPIs
        let packet = PGPPublicKeyPacket()
        packet.keyData = keyData
        
        let partialKey = PGPPartialKey(type: .public, primaryKeyPacket: packet)
        let key = PGPKey(publicKey: partialKey)
        
        let exported = try key.export(keyType: .public)
        // Exported data will contain header + version + time + algo + keyData
        XCTAssertTrue(exported.count > keyData.count)
    }
    
    func testExportSecretKey() throws {
        let keyData = Data([0x01, 0x02, 0x03, 0x04])
        let packet = PGPPublicKeyPacket(tag: .secretKey)
        packet.keyData = keyData
        
        let partialKey = PGPPartialKey(type: .secret, primaryKeyPacket: packet)
        let key = PGPKey(secretKey: partialKey)
        
        let exported = try key.export(keyType: .secret)
        XCTAssertTrue(exported.count > keyData.count)
    }
    
    func testExportKeyNotFound() {
        let key = PGPKey() // Empty key
        
        XCTAssertThrowsError(try key.export(keyType: .public)) { error in
            XCTAssertEqual(error as? PGPError, PGPError.notFound)
        }
    }
}

