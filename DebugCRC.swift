import Foundation
@testable import SwiftPGP

let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
let crc24 = data.pgpCRC24
let crcBase64 = Data([
    UInt8((crc24 >> 16) & 0xFF),
    UInt8((crc24 >> 8) & 0xFF),
    UInt8(crc24 & 0xFF)
]).base64EncodedString()

print("Data: \(data.map { String(format: "%02X", $0) })")
print("CRC24 (Hex): \(String(format: "%06X", crc24))")
print("CRC24 (Base64): \(crcBase64)")

