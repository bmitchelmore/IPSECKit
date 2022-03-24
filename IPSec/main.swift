//
//  main.swift
//  IPSec
//
//  Created by Blair Mitchelmore on 2019-11-18.
//  Copyright © 2019 Blair Mitchelmore. All rights reserved.
//

import Foundation
import Network
import BigInt
import CommonCrypto
import CryptoKit


private let hexDigits = Array("0123456789abcdef".utf16)
extension Data {
    /// Generate a hex string from Data
    var hex: String {
        let chars = [unichar](unsafeUninitializedCapacity: 2 * count) { (buffer, initializedCount) in
            for (idx, byte) in self.enumerated() {
                buffer[2 * idx] = hexDigits[Int(byte >> 4)]
                buffer[2 * idx + 1] = hexDigits[Int(byte & 15)]
            }
            initializedCount = count * 2
        }
        return String.init(utf16CodeUnits: chars, count: chars.count)
    }
}

//class Dialogue {
//    private let connection: NWConnection
//    private let provider: PacketProvider
//
//    init(connection: NWConnection) {
//        self.connection = connection
//        self.provider = connection
//    }
//
//    func send<S: Sendable, R: Receivable>(data: S, completion: @escaping (Result<R, Error>) -> Void) {
//
//    }
//}

extension Result where Success == Void {
    static var success: Result<Success,Failure> {
        .success(())
    }

    var success: Bool {
        do {
            try get()
            return true
        } catch {
            return false
        }
    }

    var failure: Bool {
        return !success
    }

    var error: Failure? {
        guard case let .failure(error) = self else {
            return nil
        }
        return error
    }
}

protocol PacketProvider {
    func receivePacket(completion: @escaping (Result<Data,Error>) -> Void)
}

protocol PacketDispatcher {
    func sendPacket(_ data: Data, completion: @escaping (Result<Void,Error>) -> Void)
}
//
//protocol Sendable {
//    func buildPackets(completion: @escaping (Result<Data,Error>) -> Void)
//}
//
//protocol Receivable {
//    static func receive(from provider: PacketProvider, completion: @escaping (Result<Self,Error>) -> Void)
//}

struct EmptyPacketError: Error {

}

extension NWConnection: PacketProvider {
    func receivePacket(completion: @escaping (Result<Data, Error>) -> Void) {
        let maker: () -> (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void = { [weak self] () in
            var all = Data()
            func callback(_ data: Data?, _ context: NWConnection.ContentContext?, _ isComplete: Bool, _ error: NWError?) {
                if let error = error {
                    completion(.failure(error))
                } else if let data = data {
                    all.append(data)
                    if isComplete {
                        completion(.success(all))
                    } else {
                        self?.receiveMessage(completion: callback)
                    }
                } else if isComplete, !all.isEmpty {
                    completion(.success(all))
                } else {
                    completion(.failure(EmptyPacketError()))
                }
            }
            return callback
        }
        self.receiveMessage(completion: maker())
    }
}

extension NWConnection: PacketDispatcher {
    func sendPacket(_ data: Data, completion: @escaping (Result<Void, Error>) -> Void) {
        self.send(content: data, completion: .contentProcessed({ (error) in
            if let error = error {
                completion(.failure(error))
            } else {
                completion(.success)
            }
        }))
    }
}

class IKEHandshake {
    private let path: NWPath
    private let dispatcher: PacketDispatcher
    private let provider: PacketProvider
    private var completion: (Result<Void,Error>) -> Void

    private let group = IKEPacket.DHGroup.MODP_3072
    private let keyExchange: (BigUInt, BigUInt)

    private enum Step {
        case ike_init(NWPath)
        case ike_init_with_cookie(NWPath, cookie: Data)
    }

    private func generate(step: Step) throws -> IKEPacket {
        switch step {
        case .ike_init(let path), .ike_init_with_cookie(let path, cookie: _):
            let (_, publicValue) = keyExchange
            let nonceData = try Data(rand(16))
            let clientIP: IPv4Address
            let clientPort: NWEndpoint.Port
            switch path.localEndpoint {
            case let .hostPort(host: .ipv4(ipv4), port: port):
                clientIP = ipv4
                clientPort = port
            default:
                throw TunnelError.invalidLocalEndpoint
            }
            let serverIP: IPv4Address
            let serverPort: NWEndpoint.Port
            switch path.remoteEndpoint {
            case let .hostPort(host: .ipv4(ipv4), port: port):
                serverIP = ipv4
                serverPort = port
            default:
                throw TunnelError.invalidLocalEndpoint
            }

            let ispi = try rand(8)
            let rspi = repeating(0, 8)
            let mid = repeating(0, 4)

            let natSourceData: Data = {
                var data = Data()
                data.append(ispi)
                data.append(rspi)
                data.append(clientIP.rawValue)
                data.append(clientPort.rawValue.networkBytes)
                return data.sha1()
            }()
            let natDestData: Data = {
                var data = Data()
                data.append(ispi)
                data.append(rspi)
                data.append(serverIP.rawValue)
                data.append(serverPort.rawValue.networkBytes)
                return data.sha1()
            }()

            let cookie: Data?
            if case let .ike_init_with_cookie(_, cookie: data) = step {
                cookie = data
            } else {
                cookie = nil
            }

            let payloads: [IKEPacket.Payload?] = [
                .SA([
                    .IKE([
                        .ENCR(.AES_GCM_16([.KeyLength(256)])),
                        .PRF(.HMAC_SHA2_256),
                        .DH(group)
                    ])
                ]),
                .KE(
                    IKEPacket.Payload.KEData(
                        group: group,
                        data: publicValue
                    )
                ),
                .Nonce(nonceData),
                .Notify(.RedirectSupported()),
                .Notify(.NATDetectionSourceIP(natSourceData)),
                .Notify(.NATDetectionDestIP(natDestData)),
                .Notify(.IKEv2FragmentationSupported()),
                cookie.map { .Notify(.Cookie($0)) }
            ]

            let packet = IKEPacket(
                exchangeType: .IKE_SA_INIT,
                header: IKEPacket.Header(
                    ispi: ispi,
                    rspi: rspi,
                    mid: mid
                ),
                flags: .initiator,
                payloads: payloads.compactMap { $0 }
            )
            return packet
        }
    }

    init(path: NWPath, dispatcher: PacketDispatcher, provider: PacketProvider) throws {
        self.path = path
        self.dispatcher = dispatcher
        self.provider = provider
        self.completion = { _ in }
        self.keyExchange = try group.generateKeyExchangeData()
    }

    func start(completion: @escaping (Result<Void,Error>) -> Void) {
        self.completion = completion
        perform(step: .ike_init(path))
    }

    private func perform(step: Step) {
        do {
            print("Sending step: \(step)")
            let packet = try generate(step: step)
            let packet_bytes = try packet.serialize()
            dispatcher.sendPacket(packet_bytes) { [weak self] (result) in
                guard let self = self else { return }
                switch result {
                case .failure(let error):
                    self.completion(.failure(error))
                case .success(_):
                    self.provider.receivePacket { [weak self] (result) in
                        guard let self = self else { return }
                        switch result {
                        case .failure(let error):
                            self.completion(.failure(error))
                        case .success(let data):
                            do {
                                let response = try IKEPacket(data: data)
                                self.handleIkeInitResponse(response, for: packet)
                            } catch {
                                self.completion(.failure(error))
                            }
                        }
                    }
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    private func handleIkeInitResponse(_ response: IKEPacket, for initiator: IKEPacket) {
        if response.contains(.CERTREQ) {
            // respond with certs
            print("Time to send the certs!")
            guard
                let Ni = initiator.nonce,
                let Nr = response.nonce,
                let gIR = try? response.generateSharedSecret(using: keyExchange.0),
                let prf = response.prf
            else {
                return
            }
            let skeyseed = prf.generate(key: Ni + Nr, secret: gIR.serialize())
            let bytes_needed = prf.keySize * 3 + response.integrityKeySize * 2 + response.encryptionKeySize * 2
            let bytes = prf.generate_plus(
                key: skeyseed,
                secret:
                    Ni +
                    Nr +
                    initiator.header.ispi +
                    response.header.rspi,
                size: bytes_needed
            )
            do {
                var available = try DataConsumer(data: bytes)
                let SKd = try available.take(prf.keySize)
                let SKai = try available.take(response.integrityKeySize)
                let SKar = try available.take(response.integrityKeySize)
                let SKei = try available.take(response.encryptionKeySize)
                let SKer = try available.take(response.encryptionKeySize)
                let SKpi = try available.take(prf.keySize)
                let SKpr = try available.take(prf.keySize)

                let encrypted = AES.GCM.seal(<#T##message: DataProtocol##DataProtocol#>, using: <#T##SymmetricKey#>, authenticating: <#T##DataProtocol#>)
            } catch {
                print("Uh Oh! \(error)")
            }
        } else if let data = response.grab(.Cookie) {
            // respond with original request + cookie
            perform(step: .ike_init_with_cookie(path, cookie: data))
        }
    }
}

extension IKEPacket {
    var dhGroup: DHGroup? {
        for payload in payloads {
            if case .KE(let data) = payload {
                return data.group
            }
        }
        return nil
    }

    func generateSharedSecret(using privateKey: BigUInt) throws -> BigUInt {

    }

    var nonce: Data? {
        for payload in payloads {
            if case .Nonce(let data) = payload {
                return data
            }
        }
        return nil
    }

    func contains(_ type: Payload.PayloadType) -> Bool {
        return payloads.contains { $0.type == type }
    }

    func grab(_ type: Payload.NotifyData.MessageType) -> Data? {
        for payload in payloads {
            if case .Notify(let data) = payload, data.messageType == type {
                return data.messageData
            }
        }
        return nil
    }
}

class Tunnel {
    private let connection: NWConnection
    private let queue: DispatchQueue

    private let bqueue: DispatchQueue
    private let bsem: DispatchSemaphore

    private var path: NWPath? {
        didSet {
            path.map {
                print("path changed: \($0)")
                $0.localEndpoint.map { print("local: \($0)") }
                $0.remoteEndpoint.map { print("remote: \($0)") }
            }
            validPath = path != nil
        }
    }
    private var validPath: Bool = false {
        didSet {
            guard oldValue != validPath else { return }
            if validPath {
                bsem.signal()
            } else {
                bsem.wait()
            }
        }
    }

    private var startCompletion: (Result<Void,Error>) -> Void = { _ in }
    private var stopCompletion: (Result<Void,Error>) -> Void = { _ in }

    init(host: String) {
        connection = NWConnection(host: NWEndpoint.Host(host), port: 500, using: .udp)
        queue = DispatchQueue(label: "com.nortonlifelock.ios.ipsec", qos: .background, attributes: .concurrent, autoreleaseFrequency: .workItem, target: nil)
        bqueue = DispatchQueue(label: "com.nortonlifelock.ios.ipsec.bqueue", qos: .background, attributes: .concurrent, autoreleaseFrequency: .workItem, target: nil)
        bsem = DispatchSemaphore(value: 0)
    }

    private func waitForPath(completion: @escaping (Result<Void,Error>) -> Void) {
        bqueue.async { [weak self] () in
            guard let self = self else { return }
            if self.path == nil {
                self.bsem.wait()
            }
            completion(.success)
        }
    }

    private func watchForPath() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            if self.connection.state == .ready {
                self.path = self.connection.currentPath
            }
        }
        connection.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            if self.connection.state == .ready {
                self.path = self.connection.currentPath
            }
        }
        connection.betterPathUpdateHandler = { [weak self] isBetter in
            guard let self = self else { return }
            if self.connection.state == .ready {
                self.path = self.connection.currentPath
            }
        }
        connection.viabilityUpdateHandler = { [weak self] isViable in
            guard let self = self else { return }
            if self.connection.state == .ready {
                self.path = self.connection.currentPath
            }
        }
    }

    func start(completion: @escaping (Result<Void,Error>) -> Void) {
        startCompletion = completion
        watchForPath()
        connection.start(queue: queue)
        waitForPath { [weak self] result in
            guard result.success else {
                return completion(result)
            }
            guard let self = self else { return }
            guard let path = self.path else { return }
            print("Done waiting. Generating packet now")

            do {
                let dispatcher = self.connection
                let receiver = self.connection
                let handshake = try IKEHandshake(path: path, dispatcher: dispatcher, provider: receiver)
                handshake.start { (result) in
                    print("handshake result: \(result)")
                    print("handshake: \(handshake)")
                }
            } catch {
                print("handshake init error: \(error)")
            }
//
//
//            do {
//                let packet = try self.generate(step: .ike_init(path))
//                print("Packet generated. Sending now!")
//                let connection = self.connection
//                let completion: NWConnection.SendCompletion = .contentProcessed { [unowned connection] (error) in
//                    if let error = error {
//                        print("error: \(error)")
//                    } else {
//                        print("ike_init sent successfully!")
//                        connection.receiveMessage { (data, context, isComplete, error) in
//                            if let data = data {
//                                print("data: \(data.hex)")
//                                do {
//                                    let packet = try IKEPacket(data: data)
//                                    print("packet: \(packet)")
//                                } catch {
//                                    print("error parsing IKE packet: \(error)")
//                                }
//                            } else {
//                                print("data bytes: nil")
//                            }
//                            if let context = context {
//                                print("context: \(context)")
//                            } else {
//                                print("context: nil")
//                            }
//                            print("isComplete: \(isComplete)")
//                            if let error = error {
//                                print("error: \(error)")
//                            } else {
//                                print("error: nil")
//                            }
//                        }
//                    }
//                }
//                self.connection.send(
//                    content: packet,
//                    completion: completion
//                )
//            } catch {
//                print("failed to send: \(error)")
//                self.startCompletion(.failure(error))
//                self.startCompletion = { _ in }
//            }
        }
    }

    func stop(completion: @escaping (Result<Void,Error>) -> Void) {
        stopCompletion = completion
        connection.cancel()
        stopCompletion(.success(()))
        stopCompletion = { _ in }
    }
}

enum TunnelError: Error {
    case invalidLocalEndpoint
    case invalidRemoteEndpoint
}




let tunnel = Tunnel(host: "23.236.161.236")
tunnel.start { (result) in
    print("result: \(result)")
}

RunLoop.main.run()
