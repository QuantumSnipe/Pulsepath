import Foundation
import NetworkExtension
import os.log

/// Observe-only content filter. Every flow is allowed. Packet bytes are never peeked.
final class FilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: "app.pulsepath.Pulsepath.Filter", category: "observer")

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let anyFlow = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .any
        )
        let rule = NEFilterRule(networkRule: anyFlow, action: .filterData)
        // defaultAction is allow so a settings failure still fail-opens.
        let settings = NEFilterSettings(rules: [rule], defaultAction: .allow)
        apply(settings, completionHandler: completionHandler)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        if let socket = flow as? NEFilterSocketFlow {
            let remote = socket.remoteEndpoint?.debugDescription ?? "-"
            let local = socket.localEndpoint?.debugDescription ?? "-"
            log.info("flow allow family=\(socket.socketFamily, privacy: .public) remote=\(remote, privacy: .private) local=\(local, privacy: .private)")
        } else {
            log.info("flow allow non-socket")
        }
        return .allow()
    }
}
