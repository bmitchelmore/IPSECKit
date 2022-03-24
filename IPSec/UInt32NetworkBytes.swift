//
//  UInt32NetworkBytes.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-11-30.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation

extension UInt32 {
    struct OutOfBoundsError: Error {
        
    }
    
    init(networkBytes data: Data) throws {
        guard data.count >= 4 else {
            throw OutOfBoundsError()
        }
        let value = data.withUnsafeBytes { ptr in
            ptr.load(as: UInt32.self)
        }
        self = UInt32(bigEndian: value)
    }
    
    var networkBytes: Data {
        var bytes = [UInt8](repeating: 0x0, count: 4)
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
