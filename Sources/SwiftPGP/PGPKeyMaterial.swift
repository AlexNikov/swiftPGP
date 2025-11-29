//
//  PGPKeyMaterial.swift
//  SwiftPGP
//

import Foundation

/// Holds generated key material (MPIs)
public class PGPKeyMaterial {
    public var n: PGPMPI?
    public var e: PGPMPI?
    public var d: PGPMPI?
    public var p: PGPMPI?
    public var q: PGPMPI?
    public var u: PGPMPI?
    
    public init() {}
}

