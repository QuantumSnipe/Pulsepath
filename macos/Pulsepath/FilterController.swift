import Combine
import Foundation
import NetworkExtension
import SystemExtensions
import SwiftUI

@MainActor
final class FilterController: NSObject, ObservableObject {
    enum State: Equatable {
        case unknown
        case inactive
        case waitingForApproval
        case observing
        case failed(String)
    }

    @Published private(set) var state: State = .unknown
    @Published private(set) var message: String?

    var canEnable: Bool {
        switch state {
        case .inactive, .failed, .unknown: return true
        default: return false
        }
    }

    var canDisable: Bool {
        switch state {
        case .observing, .waitingForApproval: return true
        default: return false
        }
    }

    var statusText: String {
        switch state {
        case .unknown: return "Checking filter status…"
        case .inactive: return "Observer off. Python lsof/nettop still works from the repo root."
        case .waitingForApproval: return "Waiting for the system-extension prompt."
        case .observing: return "Observer on. Flows are allowed; metadata is logged locally by the extension."
        case .failed(let reason): return "Observer failed: \(reason)"
        }
    }

    var statusColor: Color {
        switch state {
        case .observing: return .green
        case .waitingForApproval: return .yellow
        case .failed: return .red
        default: return .gray
        }
    }

    func refresh() {
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            Task { @MainActor in
                guard let self else { return }
                if let error {
                    self.state = .failed(error.localizedDescription)
                    return
                }
                let manager = NEFilterManager.shared()
                if manager.isEnabled, manager.providerConfiguration != nil {
                    self.state = .observing
                } else {
                    self.state = .inactive
                }
            }
        }
    }

    private var enabling = false

    func enable() {
        message = nil
        enabling = true
        state = .waitingForApproval
        let identifier = FilterController.extensionBundleIdentifier
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func disable() {
        message = nil
        enabling = false
        let identifier = FilterController.extensionBundleIdentifier
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        NEFilterManager.shared().loadFromPreferences { error in
            let manager = NEFilterManager.shared()
            manager.isEnabled = false
            manager.saveToPreferences { saveError in
                Task { @MainActor in
                    if let error = saveError ?? error {
                        self.message = error.localizedDescription
                    }
                    self.refresh()
                }
            }
        }
    }

    fileprivate static var extensionBundleIdentifier: String {
        Bundle.main.bundleIdentifier.flatMap { "\($0).Filter" } ?? "app.pulsepath.Pulsepath.Filter"
    }

    fileprivate func enableFilterConfiguration() {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error {
                Task { @MainActor in
                    self.state = .failed(error.localizedDescription)
                }
                return
            }
            if manager.providerConfiguration == nil {
                let configuration = NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterPackets = false
                configuration.username = "Pulsepath"
                configuration.organization = "Pulsepath"
                configuration.filterDataProviderBundleIdentifier = FilterController.extensionBundleIdentifier
                manager.providerConfiguration = configuration
            }
            manager.isEnabled = true
            manager.saveToPreferences { saveError in
                Task { @MainActor in
                    if let saveError {
                        self.state = .failed(saveError.localizedDescription)
                    } else {
                        self.state = .observing
                        self.message = "Content filter is enabled. Disable it here before deleting the app."
                    }
                }
            }
        }
    }
}

extension FilterController: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            switch result {
            case .completed:
                if self.enabling {
                    self.enableFilterConfiguration()
                } else {
                    self.refresh()
                }
            case .willCompleteAfterReboot:
                self.message = "macOS will finish the extension change after a reboot."
                self.state = .waitingForApproval
            @unknown default:
                self.state = .failed("Unexpected system-extension result.")
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            self.state = .failed(error.localizedDescription)
        }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.state = .waitingForApproval
            self.message = "Approve Pulsepath in System Settings to start observing."
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}
