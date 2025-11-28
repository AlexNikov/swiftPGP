//  PGPFoundation.swift
//  SwiftPGP

import Foundation

/// Foundation utilities for SwiftPGP
public struct PGPFoundation {
    
    /// Safe cast function
    public static func cast<T>(_ obj: Any?, to type: T.Type) -> T? {
        return obj as? T
    }
    
    /// Compare two objects for equality
    public static func equalObjects(_ obj1: Any?, _ obj2: Any?) -> Bool {
        // Check for nil
        guard let obj1 = obj1, let obj2 = obj2 else {
            return obj1 == nil && obj2 == nil
        }
        
        // Use NSObject's isEqual if available
        if let nsObj1 = obj1 as? NSObject, let nsObj2 = obj2 as? NSObject {
            return nsObj1 === nsObj2 || nsObj1.isEqual(nsObj2)
        }
        
        // Fallback to string comparison
        return String(describing: obj1) == String(describing: obj2)
    }
}

