//  PGPArmor.swift
//  SwiftPGP

import Foundation

/// ASCII Armor message.
public struct PGPArmor {
    
    private static let armorHeaderPrefix = "-----BEGIN PGP "
    private static let armorFooterPrefix = "-----END PGP "
    private static let armorSuffix = "-----"
    
    private static func armorHeader(for type: PGPArmorType, part: Int = 1, of totalParts: Int = 1) -> String {
        switch type {
        case .message:
            return "\(armorHeaderPrefix)MESSAGE\(armorSuffix)"
        case .publicKey:
            return "\(armorHeaderPrefix)PUBLIC KEY BLOCK\(armorSuffix)"
        case .secretKey:
            return "\(armorHeaderPrefix)PRIVATE KEY BLOCK\(armorSuffix)"
        case .signature:
            return "\(armorHeaderPrefix)SIGNATURE\(armorSuffix)"
        case .multipartMessagePartXOfY:
            return "\(armorHeaderPrefix)MESSAGE, PART \(part)/\(totalParts)\(armorSuffix)"
        case .multipartMessagePartX:
            return "\(armorHeaderPrefix)MESSAGE, PART \(part)\(armorSuffix)"
        case .cleartextSignedMessage:
            return "\(armorHeaderPrefix)SIGNED MESSAGE\(armorSuffix)"
        }
    }
    
    private static func armorFooter(for type: PGPArmorType, part: Int = 1, of totalParts: Int = 1) -> String {
        switch type {
        case .message:
            return "\(armorFooterPrefix)MESSAGE\(armorSuffix)"
        case .publicKey:
            return "\(armorFooterPrefix)PUBLIC KEY BLOCK\(armorSuffix)"
        case .secretKey:
            return "\(armorFooterPrefix)PRIVATE KEY BLOCK\(armorSuffix)"
        case .signature:
            return "\(armorFooterPrefix)SIGNATURE\(armorSuffix)"
        case .multipartMessagePartXOfY:
            return "\(armorFooterPrefix)MESSAGE, PART \(part)/\(totalParts)\(armorSuffix)"
        case .multipartMessagePartX:
            return "\(armorFooterPrefix)MESSAGE, PART \(part)\(armorSuffix)"
        case .cleartextSignedMessage:
            return "\(armorFooterPrefix)SIGNED MESSAGE\(armorSuffix)"
        }
    }
    
    /// Convert binary PGP message to ASCII armored format.
    public static func armored(_ data: Data, as type: PGPArmorType, part: Int = 1, of totalParts: Int = 1) -> String {
        let base64String = data.base64EncodedString()
        
        // Split into 64-character lines
        let lines = base64String.chunked(into: 64)
        let body = lines.joined(separator: "\n")
        
        let header = armorHeader(for: type, part: part, of: totalParts)
        let footer = armorFooter(for: type, part: part, of: totalParts)
        
        return "\(header)\n\n\(body)\n\n\(footer)\n"
    }
    
    /// Convert ASCII armored PGP message to binary format.
    public static func readArmored(_ string: String) throws -> Data {
        let lines = string.components(separatedBy: .newlines)
        
        var inBody = false
        var base64Lines: [String] = []
        
        for line in lines {
            if line.hasPrefix(armorHeaderPrefix) {
                inBody = false
                continue
            }
            if line.hasPrefix(armorFooterPrefix) {
                break
            }
            if inBody {
                base64Lines.append(line.trimmingCharacters(in: .whitespaces))
            }
            if line.isEmpty && !inBody {
                inBody = true
            }
        }
        
        let base64String = base64Lines.joined()
        guard let data = Data(base64Encoded: base64String) else {
            throw PGPError.invalidMessage
        }
        
        return data
    }
    
    /// Whether the data is PGP ASCII armored message.
    public static func isArmoredData(_ data: Data) -> Bool {
        guard let string = String(data: data, encoding: .utf8) else {
            return false
        }
        return string.contains(armorHeaderPrefix)
    }
    
    /// Helper function to convert input data (ASCII or binary) to array of PGP messages.
    public static func convertArmoredMessage2BinaryBlocksWhenNecessary(_ data: Data) throws -> [Data] {
        if isArmoredData(data) {
            guard let string = String(data: data, encoding: .utf8) else {
                throw PGPError.invalidMessage
            }
            let binary = try readArmored(string)
            return [binary]
        }
        return [data]
    }
}

// MARK: - String Extension

extension String {
    func chunked(into size: Int) -> [String] {
        var chunks: [String] = []
        var index = self.startIndex
        
        while index < self.endIndex {
            let endIndex = self.index(index, offsetBy: size, limitedBy: self.endIndex) ?? self.endIndex
            chunks.append(String(self[index..<endIndex]))
            index = endIndex
        }
        
        return chunks
    }
}

