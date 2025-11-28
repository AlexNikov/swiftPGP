//  PGPUser.swift
//  SwiftPGP

import Foundation

/// PGP User
public class PGPUser: NSObject, NSCopying {
    
    public var userID: String
    public var image: Data?
    
    public init(userID: String, image: Data? = nil) {
        self.userID = userID
        self.image = image
        super.init()
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        return PGPUser(userID: userID, image: image)
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? PGPUser else {
            return false
        }
        return self.userID == other.userID
    }
    
    public override var hash: Int {
        return userID.hashValue
    }
}

