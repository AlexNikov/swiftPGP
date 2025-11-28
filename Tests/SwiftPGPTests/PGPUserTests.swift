//  PGPUserTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPUserTests: XCTestCase {
    
    func testUserCreation() {
        let userID = "Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>"
        let user = PGPUser(userID: userID)
        
        XCTAssertEqual(user.userID, userID)
        XCTAssertNil(user.image)
    }
    
    func testUserWithImage() {
        let userID = "Test User <test@example.com>"
        let imageData = Data([0x01, 0x02, 0x03, 0x04])
        let user = PGPUser(userID: userID, image: imageData)
        
        XCTAssertEqual(user.userID, userID)
        XCTAssertEqual(user.image, imageData)
    }
    
    func testUserEquality() {
        let userID = "Test User <test@example.com>"
        let user1 = PGPUser(userID: userID)
        let user2 = PGPUser(userID: userID)
        let user3 = PGPUser(userID: "Different User <different@example.com>")
        
        XCTAssertEqual(user1, user2)
        XCTAssertNotEqual(user1, user3)
    }
    
    func testUserCopy() {
        let userID = "Test User <test@example.com>"
        let imageData = Data([0x01, 0x02, 0x03])
        let user = PGPUser(userID: userID, image: imageData)
        
        let copied = user.copy() as? PGPUser
        XCTAssertNotNil(copied)
        XCTAssertEqual(user.userID, copied?.userID)
        XCTAssertEqual(user.image, copied?.image)
        XCTAssertFalse(user === copied, "Copy should create a new instance")
    }
}

