//
//  UInt16NetworkBytes.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-12-03.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation

extension UInt16 {
    struct OutOfBoundsError: Error {
        
    }
    
    init(networkBytes data: Data) throws {
        guard data.count >= 2 else {
            throw OutOfBoundsError()
        }
        let value = data.withUnsafeBytes { ptr in
            ptr.load(as: UInt16.self)
        }
        self = UInt16(bigEndian: value)
    }
    
    var networkBytes: Data {
        var bytes = [UInt8](repeating: 0x0, count: 2)
        var value = self
        var idx = bytes.count - 1
        while value != 0 {
            bytes[idx] = UInt8(value & 0xff)
            value >>= 8
            idx -= 1
        }
        return Data(bytes)
    }
}
