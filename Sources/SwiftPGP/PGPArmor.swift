//  PGPArmor.swift
//  SwiftPGP
//

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
        let headers = ["Version": "SwiftPGP", "Comment": "https://github.com/krzyzanowskim/ObjectivePGP", "Charset": "UTF-8"]
        
        var armoredMessage = ""
        
        // Header
        let headerLine = armorHeader(for: type, part: part, of: totalParts)
        armoredMessage += headerLine + "\n"
        
        // Armor Headers
        for (key, value) in headers {
            armoredMessage += "\(key): \(value)\n"
        }
        armoredMessage += "\n"
        
        // Body (Base64)
        let base64String = data.base64EncodedString()
        let lines = base64String.chunked(into: 64)
        let body = lines.joined(separator: "\n")
        armoredMessage += body + "\n"
        
        // Checksum (CRC24)
        let crc24 = data.pgpCRC24
        var crcBytes = [UInt8](repeating: 0, count: 3)
        crcBytes[0] = UInt8((crc24 >> 16) & 0xFF)
        crcBytes[1] = UInt8((crc24 >> 8) & 0xFF)
        crcBytes[2] = UInt8(crc24 & 0xFF)
        let checksumData = Data(crcBytes)
        let checksumBase64 = checksumData.base64EncodedString()
        
        armoredMessage += "=" + checksumBase64 + "\n"
        
        // Footer
        let footerLine = armorFooter(for: type, part: part, of: totalParts)
        armoredMessage += footerLine + "\n"
        
        return armoredMessage
    }
    
    /// Convert ASCII armored PGP message to binary format.
    public static func readArmored(_ string: String) throws -> Data {
        let lines = string.components(separatedBy: .newlines)
        
        var inBody = false
        var base64Lines: [String] = []
        var checksumLine: String?
        
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            
            if trimmedLine.hasPrefix(armorHeaderPrefix) {
                inBody = false
                continue
            }
            
            if trimmedLine.hasPrefix(armorFooterPrefix) {
                break
            }
            
            // Check for checksum
            if trimmedLine.hasPrefix("=") && checksumLine == nil {
                checksumLine = String(trimmedLine.dropFirst())
                continue
            }
            
            if inBody && !trimmedLine.isEmpty && !trimmedLine.contains(":") { // Skip empty lines and headers
                base64Lines.append(trimmedLine)
            }
            
            if trimmedLine.isEmpty && !inBody {
                inBody = true
            }
        }
        
        let base64String = base64Lines.joined()
        guard let data = Data(base64Encoded: base64String) else {
            throw PGPError.invalidMessage
        }
        
        // Verify Checksum if present
        if let checksumBase64 = checksumLine {
            guard let checksumData = Data(base64Encoded: checksumBase64), checksumData.count == 3 else {
                throw PGPError.invalidMessage // Invalid checksum format
            }
            
            let expectedCRC = (UInt32(checksumData[0]) << 16) | (UInt32(checksumData[1]) << 8) | UInt32(checksumData[2])
            let actualCRC = data.pgpCRC24
            
            if expectedCRC != actualCRC {
                throw PGPError.invalidMessage // Checksum mismatch
            }
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
