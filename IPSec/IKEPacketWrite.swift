//
//  IKEPacketWrite.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-12-07.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation
import BigInt

private var primes: [IKEPacket.DHGroup:BigUInt] = [
    .MODP_3072: BigUInt(
        """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
        43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
        """
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .lowercased(),
        radix: 16
    )!
]

extension IKEPacket.DHGroup {
    private var bytesNeeded: Int {
        switch self {
        case .MODP_3072: return 384
        }
    }
    private var generator: BigUInt {
        return BigUInt(2)
    }
    private var prime: BigUInt {
        return primes[self]!
    }
    func generateKeyExchangeData() throws -> (privateKey: BigUInt, publicValue: BigUInt) {
        let privateKey = try BigUInt(Data(rand(bytesNeeded)))
        return (
            privateKey: privateKey,
            publicValue: try keyExchangeData(for: privateKey)
        )
    }
    func keyExchangeData(for privateKey: BigUInt) throws -> BigUInt {
        let start = ProcessInfo.processInfo.systemUptime
        let result = generator.power(privateKey, modulus: prime)
        let end = ProcessInfo.processInfo.systemUptime
        print("generated key exchange data. took \(end - start)s")
        return result
    }
    func generateSharedSecret(for privateKey: BigUInt, from publicValue: BigUInt) throws -> BigUInt {
        let start = ProcessInfo.processInfo.systemUptime
        let result = publicValue.power(privateKey, modulus: prime)
        let end = ProcessInfo.processInfo.systemUptime
        print("generated shared secret data. took \(end - start)s")
        return result
    }
}

extension IKEPacket {
    private func serializeHeader() throws -> Data {
        var data = Data()
        data.append(Data(header.ispi))
        data.append(Data(header.rspi))
        if let payload = payloads.first {
            data.append(payload.type.rawValue)
        } else {
            data.append(0x00)
        }
        data.append(0x20) // IKEv2 2.0
        data.append(exchangeType.rawValue)
        data.append(flags.rawValue)
        data.append(Data(header.mid))

        return data
    }
    func serialize() throws -> Data {
        print("packet struct: \(self)")
        let headerMinusLength = try serializeHeader()
        var payloadBytes = Data()
        for (idx, payload) in payloads.enumerated() {
            let nextPayload = payloads.indices.contains(idx + 1) ? payloads[idx + 1] : nil
            let bytes = try payload.serialize(header: header, nextPayload: nextPayload)
            payloadBytes.append(bytes)
        }

        let packet = Data(
            headerMinusLength: headerMinusLength,
            payloadBytes: payloadBytes,
            lengthWidth: 4
        )
        print("packet data: \(packet.hex)")

        return packet
    }
}

extension IKEPacket.Payload {
    func serialize(header: IKEPacket.Header, nextPayload: IKEPacket.Payload?) throws -> Data {
        var headerMinusLength = Data()
        headerMinusLength.append(nextPayload?.type.rawValue ?? 0)
        headerMinusLength.append(0) // critical bit + reserved space

        var payloadBytes = Data()
        switch self {
        case .SA(let proposals):
            payloadBytes.append(try proposals.serialize())
        case .KE(let data):
            payloadBytes.append(data.group.rawValue.networkBytes)
            payloadBytes.append(Data(repeating(0, 2))) // reserved
            payloadBytes.append(data.data.serialize())
        case .Nonce(let data):
            payloadBytes.append(data)
        case .Notify(let data):
            payloadBytes.append(data.protocolId)
            if let spi = data.spi {
                payloadBytes.append(UInt8(spi.count))
            } else {
                payloadBytes.append(0)
            }
            payloadBytes.append(data.messageType.rawValue.networkBytes)
            if let spi = data.spi {
                payloadBytes.append(spi)
            }
            if let data = data.messageData {
                payloadBytes.append(data)
            }
        case let .CERTREQ(encoding, cas):
            payloadBytes.append(encoding.rawValue)
            for ca in cas {
                payloadBytes.append(ca)
            }
        }

        return Data(
            headerMinusLength: headerMinusLength,
            payloadBytes: payloadBytes
        )
    }
}

extension Array where Element == IKEPacket.Payload.SAProposal {
    func serialize() throws -> Data {
        var data = Data()
        for (idx, proposal) in enumerated() {
            var headerMinusLength = Data()
            if indices.contains(idx + 1) {
                headerMinusLength.append(2)
            } else {
                headerMinusLength.append(0)
            }
            headerMinusLength.append(0) // RESERVED

            var payloadBytes = Data()
            payloadBytes.append(UInt8(idx + 1)) // Proposal #
            switch proposal {
            case .IKE(let transforms):
                payloadBytes.append(IKEPacket.Payload.SAProposal.ProposalType.IKE.rawValue) // Proposal ID
                payloadBytes.append(0) // SPI size (No SPI used in IKE SA)
                payloadBytes.append(UInt8(transforms.count))
                payloadBytes.append(try transforms.serialize())
            }

            data.append(Data(headerMinusLength: headerMinusLength, payloadBytes: payloadBytes))
        }
        return data
    }
}

extension Array where Element == IKEPacket.Payload.SAProposal.IKETransform {
    func serialize() throws -> Data {
        var data = Data()
        for (idx, transform) in enumerated() {
            var headerMinusLength = Data()
            if indices.contains(idx + 1) {
                headerMinusLength.append(3)
            } else {
                headerMinusLength.append(0)
            }
            headerMinusLength.append(0) // RESERVED

            var payloadBytes = Data()
            switch transform {
            case .DH(let group):
                payloadBytes.append(IKEPacket.Payload.SAProposal.IKETransform.TransformType.DH.rawValue)
                payloadBytes.append(0)
                payloadBytes.append(group.rawValue.networkBytes)
            case .ENCR(let transform):
                payloadBytes.append(IKEPacket.Payload.SAProposal.IKETransform.TransformType.ENCR.rawValue)
                payloadBytes.append(0)
                switch transform {
                case .AES_GCM_16(let attrs):
                    payloadBytes.append(IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRType.AES_GCM_16.rawValue.networkBytes)
                    for attr in attrs {
                        payloadBytes.append(try attr.serialize())
                    }
                }
            case .PRF(let transform):
                payloadBytes.append(IKEPacket.Payload.SAProposal.IKETransform.TransformType.PRF.rawValue)
                payloadBytes.append(0)
                payloadBytes.append(transform.rawValue.networkBytes)
            }

            data.append(Data(headerMinusLength: headerMinusLength, payloadBytes: payloadBytes))
        }
        return data
    }
}

extension IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRAttribute {
    func serialize() throws -> Data {
        switch self {
        case .KeyLength(let length):
            let typeValue = IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRAttribute.ENCRAttributeType.KeyLength.rawValue
            var bytes = typeValue.networkBytes
            bytes[0] |= 0x80 // enable TV format bit flag
            return bytes + length.networkBytes
        }
    }
}
