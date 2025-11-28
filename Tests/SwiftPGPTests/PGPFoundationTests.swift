//  PGPFoundationTests.swift
//  SwiftPGPTests

import XCTest
@testable import SwiftPGP

final class PGPFoundationTests: XCTestCase {
    
    func testCast() {
        let string = "test"
        let casted = PGPFoundation.cast(string, to: String.self)
        XCTAssertNotNil(casted)
        XCTAssertEqual(casted, "test")
        
        let failedCast = PGPFoundation.cast(string, to: Int.self)
        XCTAssertNil(failedCast)
    }
    
    func testEqualObjectsWithNil() {
        XCTAssertTrue(PGPFoundation.equalObjects(nil, nil))
        XCTAssertFalse(PGPFoundation.equalObjects("test", nil))
        XCTAssertFalse(PGPFoundation.equalObjects(nil, "test"))
    }
    
    func testEqualObjectsWithNSObject() {
        let user1 = PGPUser(userID: "Test User <test@example.com>")
        let user2 = PGPUser(userID: "Test User <test@example.com>")
        let user3 = PGPUser(userID: "Different User <different@example.com>")
        
        XCTAssertTrue(PGPFoundation.equalObjects(user1, user2))
        XCTAssertFalse(PGPFoundation.equalObjects(user1, user3))
    }
    
    func testEqualObjectsWithSameInstance() {
        let user = PGPUser(userID: "Test User <test@example.com>")
        XCTAssertTrue(PGPFoundation.equalObjects(user, user))
    }
}

