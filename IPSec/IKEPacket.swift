//
//  IKEPacket.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-11-20.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation
import BigInt
import Network

struct IKEPacket {
    struct Header {
        let ispi: Data // 8 octets (UInt64)
        let rspi: Data // 8 octets (UInt64)
        let mid: Data // 4 octets (UInt32)
    }
    enum ExchangeType: UInt8 {
        case IKE_SA_INIT = 34
        case IKE_AUTH = 35
        case CREATE_CHILD_SA = 36
        case INFORMATIONAL = 37
    }
    enum DHGroup: UInt16 {
        case MODP_3072 = 15
    }
    struct Flags: OptionSet {
        let rawValue: UInt8

        static let response = Flags(rawValue: 0b0010_0000)
        static let version = Flags(rawValue: 0b0001_0000)
        static let initiator = Flags(rawValue: 0b0000_1000)
    }
    enum Payload {
        enum PayloadType: UInt8 {
            case None = 0
            case SA = 33
            case KE = 34
            case CERTREQ = 38
            case Nonce = 40
            case Notify = 41
        }
        enum SAProposal {
            enum ProposalType: UInt8 {
                case None = 0
                case IKE = 1
            }
            enum IKETransform {
                enum TransformType: UInt8 {
                    case ENCR = 1 // Encryption Algorithm (IKE and ESP)
                    case PRF = 2 // Pseudo-random Function (IKE)
                    case DH = 4 // Diffie-Hellman Group (IKE, optional in AH & ESP)
                }
                enum ENCRTransform {
                    enum ENCRType: UInt16 {
                        case AES_GCM_16 = 20
                    }
                    enum ENCRAttribute {
                        enum ENCRAttributeType: UInt16 {
                            case KeyLength = 14
                        }
                        case KeyLength(UInt16)
                    }
                    case AES_GCM_16([ENCRAttribute])
                }
                enum PRFTransform: UInt16 {
                    case HMAC_SHA2_256 = 5
                }
                case ENCR(ENCRTransform) // Encryption Algorithm (IKE and ESP)
                case PRF(PRFTransform) // Pseudo-random Function (IKE)
                case DH(DHGroup) // Diffie-Hellman Group (IKE, optional in AH & ESP)
            }
            case IKE([IKETransform])
        }
        struct KEData {
            let group: DHGroup
            let data: BigUInt
        }
        struct NotifyData {
            enum MessageType: UInt16 {
                case RedirectSupported = 16406
                case NATDetectionSourceIP = 16388
                case NATDetectionDestIP = 16389
                case Cookie = 16390
                case IKEv2FragmentationSupported = 16430
            }
            let protocolId: UInt8
            let spi: Data?
            let messageType: MessageType
            let messageData: Data?

            static func RedirectSupported() -> Self {
                return NotifyData(
                    protocolId: 0,
                    spi: nil,
                    messageType: .RedirectSupported,
                    messageData: nil
                )
            }
            static func IKEv2FragmentationSupported() -> Self {
                return NotifyData(
                    protocolId: 0,
                    spi: nil,
                    messageType: .IKEv2FragmentationSupported,
                    messageData: nil
                )
            }
            static func NATDetectionSourceIP(_ data: Data) -> Self {
                return NotifyData(
                    protocolId: 0,
                    spi: nil,
                    messageType: .NATDetectionSourceIP,
                    messageData: data
                )
            }
            static func NATDetectionDestIP(_ data: Data) -> Self {
                return NotifyData(
                    protocolId: 0,
                    spi: nil,
                    messageType: .NATDetectionDestIP,
                    messageData: data
                )
            }
            static func Cookie(_ data: Data) -> Self {
                return NotifyData(
                    protocolId: 0,
                    spi: nil,
                    messageType: .Cookie,
                    messageData: data
                )
            }
        }
        enum CertificateEncoding: UInt8 {
            case X509CertificateSignature = 4
        }
        typealias CertificationAuthorities = [Data]
        case SA([SAProposal])
        case KE(KEData)
        case Nonce(Data)
        case Notify(NotifyData)
        case CERTREQ(CertificateEncoding,CertificationAuthorities)
    }
    let exchangeType: ExchangeType
    let header: Header
    let flags: Flags
    let payloads: [Payload]
}

extension IKEPacket.Payload.SAProposal.IKETransform.PRFTransform {
    var keySize: UInt {
        switch self {
        case .HMAC_SHA2_256: return 32
        }
    }
    func generate(key: Data, secret: Data) -> Data {
        return secret.hmac_sha256(key: key)
    }
    func generate_plus(key: Data, secret: Data, size: UInt) -> Data {
        var data = Data()
        var previous = Data()
        var iteration: UInt8 = 0x01;
        while data.count < size {
            previous = generate(key: key, secret: previous + secret + [iteration])
            iteration += 1;
            data.append(previous)
        }
        return data
    }
}

extension IKEPacket.Payload.SAProposal.IKETransform.ENCRTransform {
    var encryptionKeySize: UInt {
        switch self {
        case .AES_GCM_16(let attrs):
            for case .KeyLength(let len) in attrs {
                return UInt(len / 8)
            }
            return 16
        }
    }
    var integrityKeySize: UInt {
        switch self {
        case .AES_GCM_16(_):
            return 16
        }
    }
}

extension IKEPacket {
    var prf: Payload.SAProposal.IKETransform.PRFTransform? {
        for case .SA(let proposals) in payloads {
            for case .IKE(let transforms) in proposals {
                for case .PRF(let fn) in transforms {
                    return fn
                }
            }
        }
        return nil
    }
}

extension IKEPacket {
    var prfKeySize: UInt {
        for case .SA(let proposals) in payloads {
            for case .IKE(let transforms) in proposals {
                for case .PRF(let fn) in transforms {
                    return fn.keySize
                }
            }
        }
        return 0
    }
    var integrityKeySize: UInt {
        for case .SA(let proposals) in payloads {
            for case .IKE(let transforms) in proposals {
                for case .ENCR(let fn) in transforms {
                    return fn.integrityKeySize
                }
            }
        }
    }
    var encryptionKeySize: UInt {
        for case .SA(let proposals) in payloads {
            for case .IKE(let transforms) in proposals {
                for case .ENCR(let fn) in transforms {
                    return fn.encryptionKeySize
                }
            }
        }
    }
}

extension IKEPacket.Payload {
    var type: PayloadType {
        switch self {
        case .SA: return .SA
        case .KE: return .KE
        case .Nonce: return .Nonce
        case .Notify: return .Notify
        case .CERTREQ: return .CERTREQ
        }
    }
}
