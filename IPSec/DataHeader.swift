//
//  DataHeader.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-11-20.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation

extension Data {
    init(headerMinusLength: Data, payloadBytes: Data, lengthWidth: Int = 2) {
        self.init()
        let packetSize = headerMinusLength.count + payloadBytes.count + lengthWidth
        append(headerMinusLength)
        switch lengthWidth {
        case 2:
            let value = UInt16(packetSize)
            let bytes = value.networkBytes
            append(bytes)
        case 4:
            let value = UInt32(packetSize)
            let bytes = value.networkBytes
            append(bytes)
        default:
            fatalError("Invalid lengthWidth")
        }
        append(payloadBytes)
    }
}
