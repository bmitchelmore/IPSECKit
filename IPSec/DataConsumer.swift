//
//  DataConsumer.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-12-02.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation

struct ProducedData<T> {
    let result: T
    let bytesConsumed: UInt32
}

struct DataConsumer {
    enum ConsumerError: Error {
        case outOfBounds
        case invalidConversion
    }
    
    private let data: Data
    private var offset: Int
    
    var bytesConsumed: UInt32
    
    init(data: Data, startOffset: Int = 0) throws {
        guard startOffset < data.count else {
            throw ConsumerError.outOfBounds
        }
        self.data = data
        self.offset = startOffset
        self.bytesConsumed = 0
    }

    func peek(_ count: Int) throws -> Data {
        let end = offset + count
        guard end <= data.count else {
            throw ConsumerError.outOfBounds
        }
        let result = data.subdata(in: offset..<end)
        return result
    }
    
    mutating func take(_ count: Int) throws -> Data {
        let result = try peek(count)
        offset += count
        bytesConsumed += UInt32(count)
        return result
    }
}

extension DataConsumer {
    mutating func produce<T>(using block: (inout DataConsumer) throws -> T) throws -> ProducedData<T> {
        let start = self.bytesConsumed
        let result = try block(&self)
        let end = self.bytesConsumed
        return ProducedData(
            result: result,
            bytesConsumed: end - start
        )
    }
}

extension DataConsumer {
    mutating func peekAll() throws -> Data {
        let remaining = data.count - offset
        return try peek(remaining)
    }

    mutating func peek(_ count: UInt8) throws -> Data {
        return try peek(Int(count))
    }

    mutating func peek(_ count: UInt16) throws -> Data {
        return try peek(Int(count))
    }

    mutating func peek(_ count: UInt32) throws -> Data {
        return try peek(Int(count))
    }

    mutating func peek1() throws -> UInt8 {
        return try peek(1)[0]
    }

    mutating func takeAll() throws -> Data {
        let remaining = data.count - offset
        return try take(remaining)
    }

    mutating func take(_ count: UInt) throws -> Data {
        return try take(Int(count))
    }
    
    mutating func take(_ count: UInt8) throws -> Data {
        return try take(Int(count))
    }
    
    mutating func take(_ count: UInt16) throws -> Data {
        return try take(Int(count))
    }
    
    mutating func take(_ count: UInt32) throws -> Data {
        return try take(Int(count))
    }
    
    mutating func take1() throws -> UInt8 {
        return try take(1)[0]
    }
    
    mutating func take2() throws -> UInt16 {
        return try UInt16(networkBytes: take(2))
    }
    
    mutating func take4() throws -> UInt32 {
        return try UInt32(networkBytes: take(4))
    }

    mutating func process<T>(_ count: UInt16, processor: (inout DataConsumer) throws -> T) throws -> T {
        let data = try peek(count)
        var bytes = try DataConsumer(data: data)
        let result = try processor(&bytes)
        guard count == bytes.bytesConsumed else {
            print("invalidConversion when processing \(count) bytes (only consumer \(bytes.bytesConsumed) bytes) to \(T.self): \(data.hex)")
            throw ConsumerError.invalidConversion
        }
        _ = try take(count)
        return result
    }

    mutating func process1<T>(or error: Error, processor: (UInt8) -> T?) throws -> T {
        let byte = try take1()
        guard let result = processor(byte) else {
            print("failed to convert 1 byte (\(byte)) to \(T.self)")
            throw error
        }
        return result
    }
    
    mutating func process2<T>(or error: Error, processor: (UInt16) -> T?) throws -> T {
        let byte = try take2()
        guard let result = processor(byte) else {
            print("failed to convert 2 bytes (\(byte)) to \(T.self)")
            throw error
        }
        return result
    }
}
