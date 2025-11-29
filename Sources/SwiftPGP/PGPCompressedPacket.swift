//
//  PGPCompressedPacket.swift
//  SwiftPGP
//

import Foundation

/// Compressed Data Packet (Tag 8)
public class PGPCompressedPacket: PGPPacket {
    
    public var compressionAlgorithm: PGPCompressionAlgorithm = .uncompressed
    public var decompressedData: Data = Data()
    
    public init() {
        super.init(tag: .compressedData)
    }
    
    public init(data: Data, type: PGPCompressionAlgorithm = .zlib) {
        super.init(tag: .compressedData)
        self.decompressedData = data
        self.compressionAlgorithm = type
    }
    
    // MARK: - Parsing
    
    public override func parse(data: Data) throws {
        guard !data.isEmpty else { throw PGPError.invalidMessage }
        var offset = 0
        
        self.compressionAlgorithm = PGPCompressionAlgorithm(rawValue: data[offset]) ?? .uncompressed
        offset += 1
        
        let compressedData = data.subdata(in: offset..<data.count)
        
        switch compressionAlgorithm {
        case .uncompressed:
            self.decompressedData = compressedData
        case .zip, .zlib:
            // TODO: Implement ZLIB decompression
            // For now, we store raw compressed data if we can't decompress
            // Or throw error if decompression is required but not available
            // self.decompressedData = try compressedData.decompressed(using: .zlib)
            print("Warning: ZLIB decompression not implemented")
            self.decompressedData = compressedData
        case .bzip2:
            // TODO: Implement BZIP2 decompression
            print("Warning: BZIP2 decompression not implemented")
            self.decompressedData = compressedData
        }
    }
    
    // MARK: - Export
    
    public override func export() throws -> Data {
        var body = Data()
        body.append(compressionAlgorithm.rawValue)
        
        var compressedData: Data
        switch compressionAlgorithm {
        case .uncompressed:
            compressedData = decompressedData
        case .zip, .zlib:
            // TODO: Implement ZLIB compression
            // compressedData = try decompressedData.compressed(using: .zlib)
            compressedData = decompressedData // Placeholder
        case .bzip2:
            // TODO: Implement BZIP2 compression
            compressedData = decompressedData // Placeholder
        }
        
        body.append(compressedData)
        
        let header = PGPPacket.buildHeader(tag: tag, bodyLength: body.count)
        var result = header
        result.append(body)
        return result
    }
}
