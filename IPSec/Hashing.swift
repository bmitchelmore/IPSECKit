//
//  Hashing.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2020-01-24.
//  Copyright © 2020 Blair Mitchelmore. All rights reserved.
//

import Foundation
import CommonCrypto

extension Data {
    func sha1() -> Data {
        let bytes = [UInt8](self)
        var buffer = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = CC_SHA1(bytes, CC_LONG(bytes.count), &buffer)
        return Data(buffer)
    }
    func sha256() -> Data {
        let bytes = [UInt8](self)
        var buffer = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = CC_SHA256(bytes, CC_LONG(bytes.count), &buffer)
        return Data(buffer)
    }
    func hmac_sha256(key: Data) -> Data {
        let key_bytes = [UInt8](key)
        let data_bytes = [UInt8](self)
        var buffer = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key_bytes, key_bytes.count, data_bytes, data_bytes.count, &buffer)
        return Data(buffer)
    }
}
