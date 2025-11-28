//  PGPExportable.swift
//  SwiftPGP

import Foundation

/// Protocol for objects that can be exported to Data
public protocol PGPExportable {
    func export() throws -> Data
}

