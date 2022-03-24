//
//  IKEPacketParse.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-12-07.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation
import BigInt

enum IKEParseError: Error {
    case headerTooShort
    case payloadTooShort
    case invalidNextPayload
    case invalidExchangeType
    case invalidIKEVersion
    case invalidPacketLength
    case invalidMessageType
    case invalidProtocolID
    case invalidProposalID
    case invalidProposalNumber
    case invalidNextTransform
    case invalidTransformLength
    case invalidTransformId
    case invalidTransformType
    case invalidTransformAttribute
    case invalidDiffieHellmanGroup
    case invalidCertificateType
    case unexpectedCriticalBit
}

extension IKEPacket.Header {
    struct HeaderContents {
        let header: IKEPacket.Header
        let exchangeType: IKEPacket.ExchangeType
        let nextPayload: IKEPacket.Payload.PayloadType
        let flags: IKEPacket.Flags
        let headerSize: UInt32
        let packetLength: UInt32
    }
    static func build(from data: Data) throws -> HeaderContents {
        do {
            var bytes = try DataConsumer(data: data)

            let ispi = try bytes.take(8)
            let rspi = try bytes.take(8)
            let nextPayloadByte = try bytes.take1()
            let version = try bytes.take1()
            let exchangeTypeByte = try bytes.take1()
            let flagsByte = try bytes.take1()
            let mid = try bytes.take(4)
            let packetLength = try bytes.take4()
            guard version == 0x20 else {
                throw IKEParseError.invalidIKEVersion
            }
            let header = IKEPacket.Header(ispi: ispi, rspi: rspi, mid: mid)
            let flags = IKEPacket.Flags(rawValue: flagsByte)
            guard let nextPayload = IKEPacket.Payload.PayloadType(rawValue: nextPayloadByte) else {
                print("unknown next payload")
                throw IKEParseError.invalidNextPayload
            }
            guard let exchangeType = IKEPacket.ExchangeType(rawValue: exchangeTypeByte) else {
                throw IKEParseError.invalidExchangeType
            }
            guard packetLength >= data.count else {
                throw IKEParseError.invalidPacketLength
            }
            return HeaderContents(
                header: header,
                exchangeType: exchangeType,
                nextPayload: nextPayload,
                flags: flags,
                headerSize: bytes.bytesConsumed,
                packetLength: packetLength
            )
        } catch DataConsumer.ConsumerError.outOfBounds {
            throw IKEParseError.headerTooShort
        }
    }
}

extension IKEPacket.Payload {
    struct PayloadContents {
        let payload: IKEPacket.Payload
        let nextPayload: IKEPacket.Payload.PayloadType
        let payloadLength: UInt16
    }
    static func build(from data: Data, expecting expectedPayload: IKEPacket.Payload.PayloadType) throws -> PayloadContents {
        do {
            var bytes = try DataConsumer(data: data)
            let nextPayload = try bytes.process1(or: IKEParseError.invalidNextPayload) {
                IKEPacket.Payload.PayloadType(rawValue: $0)
            }
            print("nextPayload: \(nextPayload)")
            let criticalPayloadByte = try bytes.take1()
            guard criticalPayloadByte == 0x0 else {
                throw IKEParseError.unexpectedCriticalBit
            }
            let payloadLength = try bytes.take2()
            let payload: IKEPacket.Payload
            switch expectedPayload {
            case .SA:
                var proposals: [SAProposal] = []
                while true {
                    let nextPayload = try bytes.take1()
                    guard nextPayload == 0 || nextPayload == 2 else {
                        throw IKEParseError.invalidProposalID
                    }
                    _ = try bytes.take1() // reserved
                    let proposalLength = try bytes.take2() - 4 // nextPayload + reserved + length
                    let proposal: SAProposal = try bytes.process(proposalLength) { bytes in
                        let proposalNumber = try bytes.take1()
                        guard proposalNumber == proposals.count + 1 else {
                            throw IKEParseError.invalidProposalNumber
                        }
                        print("Found proposal number: \(proposalNumber)")
                        let proposalId = try bytes.process1(or: IKEParseError.invalidProposalID) {
                            IKEPacket.Payload.SAProposal.ProposalType(rawValue: $0)
                        }
                        switch proposalId {
                        case .None:
                            throw IKEParseError.invalidProposalID
                        case .IKE:
                            let spiSize = try bytes.take1()
                            let transformCount = try bytes.take1()
                            let spi: Data?
                            if spiSize > 0 {
                                spi = try bytes.take(spiSize)
                            } else {
                                spi = nil
                            }
                            if let spi = spi {
                                print("spi found: \(spi.hex)")
                            }
                            var transforms: [SAProposal.IKETransform] = []
                            for i in 1...transformCount {
                                let start = bytes.bytesConsumed
                                let nextPayload = try bytes.take1()
                                if i == transformCount {
                                    guard nextPayload == 0 else {
                                        throw IKEParseError.invalidNextTransform
                                    }
                                } else {
                                    guard nextPayload == 3 else {
                                        throw IKEParseError.invalidNextTransform
                                    }
                                }
                                _ = try bytes.take1()
                                let transformLength = try bytes.take2()
                                let transformType = try bytes.process1(or: IKEParseError.invalidTransformType) {
                                    IKEPacket.Payload.SAProposal.IKETransform.TransformType(rawValue: $0)
                                }
                                print("found transformType: \(transformType)")
                                _ = try bytes.take1()
                                switch transformType {
                                case .ENCR:
                                    let transformId = try bytes.process2(or: IKEParseError.invalidTransformType) {
                                        IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRType(rawValue: $0)
                                    }
                                    print("found transformId: \(transformId)")
                                    switch transformId {
                                    case .AES_GCM_16:
                                        let attribute = try bytes.produce { bytes -> SAProposal.IKETransform.ENCRTransform.ENCRAttribute in
                                            let attributeFormat = try bytes.peek1() & 0x80 == 0x80
                                            if attributeFormat {
                                                let type = try bytes.process2(or: IKEParseError.invalidTransformAttribute) {
                                                    IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRAttribute.ENCRAttributeType(rawValue: $0 & 0x7fff)
                                                }
                                                switch type {
                                                case .KeyLength:
                                                    let value = try bytes.take2()
                                                    return IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRAttribute.KeyLength(value)
                                                }
                                            } else {
                                                let type = try bytes.process2(or: IKEParseError.invalidTransformAttribute) {
                                                    IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform.ENCRAttribute.ENCRAttributeType(rawValue: $0)
                                                }
                                                switch type {
                                                case .KeyLength:
                                                    throw IKEParseError.invalidTransformAttribute
                                                }
                                            }
                                        }
                                        transforms.append(.ENCR(.AES_GCM_16([attribute.result])))
                                    }
                                case .PRF:
                                    let transformType = try bytes.process2(or: IKEParseError.invalidTransformType) {
                                        IKEPacket.Payload.SAProposal.IKETransform.PRFTransform(rawValue: $0)
                                    }
                                    transforms.append(.PRF(transformType))
                                case .DH:
                                    let group = try bytes.process2(or: IKEParseError.invalidTransformType) {
                                        IKEPacket.DHGroup(rawValue: $0)
                                    }
                                    transforms.append(.DH(group))
                                }

                                let end = bytes.bytesConsumed
                                guard end - start == transformLength else {
                                    throw IKEParseError.invalidTransformLength
                                }
                            }

                            print("done with transforms: \(transforms)")
                            return SAProposal.IKE(transforms)
                        }
                    }
                    proposals.append(proposal)
                    if nextPayload == 0 {
                        break
                    }
                }
                payload = .SA(proposals)
            case .KE:
                let group = try bytes.process2(or: IKEParseError.invalidDiffieHellmanGroup) {
                    IKEPacket.DHGroup(rawValue: $0)
                }
                _ = try bytes.take2() // reserved
                let data = try bytes.take(Int(payloadLength) - Int(bytes.bytesConsumed))
                let bigint = BigUInt(data)
                let keData = IKEPacket.Payload.KEData(
                    group: group,
                    data: bigint
                )
                payload = .KE(keData)
            case .Nonce:
                let data = try bytes.take(Int(payloadLength) - Int(bytes.bytesConsumed))
                payload = .Nonce(data)
            case .Notify:
                let data = try bytes.take(Int(payloadLength) - Int(bytes.bytesConsumed))
                let info = try IKEPacket.Payload.NotifyData.build(from: data)
                payload = .Notify(info)
            case .CERTREQ:
                let encoding = try bytes.process1(or: IKEParseError.invalidCertificateType) {
                    IKEPacket.Payload.CertificateEncoding(rawValue: $0)
                }
                var remaining = Int(payloadLength) - Int(bytes.bytesConsumed)
                var hashes: [Data] = []
                while remaining > 0 {
                    let size = 20
                    let hash = try bytes.take(size)
                    hashes.append(hash)
                    remaining -= size
                }
                payload = .CERTREQ(encoding, hashes)
            case .None:
                throw IKEParseError.invalidNextPayload
            }
            return PayloadContents(
                payload: payload,
                nextPayload: nextPayload,
                payloadLength: payloadLength
            )
        } catch DataConsumer.ConsumerError.outOfBounds {
            throw IKEParseError.payloadTooShort
        }
    }
}

extension IKEPacket.Payload.NotifyData {
    static func build(from data: Data) throws -> IKEPacket.Payload.NotifyData {
        var bytes = try DataConsumer(data: data)

        let protocolId = try bytes.take1()

        let spiSizeByte = try bytes.take1()
        let messageType = try bytes.process2(or: IKEParseError.invalidMessageType) {
            IKEPacket.Payload.NotifyData.MessageType(rawValue: $0)
        }

        let spi: Data?
        if spiSizeByte != 0 {
            spi = try bytes.take(spiSizeByte)
        } else {
            spi = nil
        }

        let messageData: Data?
        switch messageType {
        case .Cookie,
             .NATDetectionDestIP,
             .NATDetectionSourceIP:
            messageData = try bytes.takeAll()
        case .IKEv2FragmentationSupported,
             .RedirectSupported:
            messageData = nil
        }

        return IKEPacket.Payload.NotifyData(
            protocolId: protocolId,
            spi: spi,
            messageType: messageType,
            messageData: messageData
        )
    }
}

extension IKEPacket {
    init(data: Data) throws {
        let contents = try Header.build(from: data)
        var payloads: [IKEPacket.Payload] = []
        var payload = Data(data.suffix(from: Int(contents.headerSize)))
        var nextPayload = contents.nextPayload
        while !payload.isEmpty {
            let contents = try Payload.build(from: payload, expecting: nextPayload)
            payloads.append(contents.payload)
            nextPayload = contents.nextPayload
            payload = Data(payload.suffix(from: Int(contents.payloadLength)))
        }
        guard nextPayload == .None else {
            throw IKEParseError.invalidNextPayload
        }

        self.exchangeType = contents.exchangeType
        self.header = contents.header
        self.flags = contents.flags
        self.payloads = payloads
    }
}
