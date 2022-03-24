//
//  Random.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-11-20.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation

extension Array {
    static func random(size: Int, using builder: @autoclosure () -> Element) -> Array {
        return [Element].init(unsafeUninitializedCapacity: size) { (buffer, initializedCount) in
            for i in 0..<size {
                buffer[i] = builder()
            }
            initializedCount = size
        }
    }
}


struct EntropyError: Error {}

func rand(_ count: Int) throws -> Data {
    var buffer = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(
        kSecRandomDefault,
        count,
        &buffer
    )
    guard status == noErr else {
        throw EntropyError()
    }
    return Data(buffer)
}

func repeating(_ builder: @autoclosure () -> UInt8, _ count: Int) -> Data {
    let bytes = [UInt8].init(unsafeUninitializedCapacity: count) { (buffer, initializedCount) in
        for i in 0..<count {
            buffer[i] = builder()
        }
        initializedCount = count
    }
    return Data(bytes)
}
