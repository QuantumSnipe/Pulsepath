import SwiftUI

struct ContentView: View {
    @ObservedObject var filter: FilterController

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Pulsepath observer")
                .font(.title2.weight(.semibold))
            Text("This macOS app loads a content-filter system extension that watches connection metadata on this Mac. It always allows traffic. It does not read message contents, and it does not phone home.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Enabling it requires a system prompt. After that, Pulsepath can see flow metadata for every app, not only sockets your user account already exposes through lsof. Disable it before deleting this app.")
                .fixedSize(horizontal: false, vertical: true)
                .foregroundStyle(.secondary)

            statusRow

            HStack {
                Button("Enable observer") {
                    filter.enable()
                }
                .disabled(!filter.canEnable)
                Button("Disable observer") {
                    filter.disable()
                }
                .disabled(!filter.canDisable)
            }

            if let message = filter.message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
        }
        .padding(24)
        .onAppear { filter.refresh() }
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(filter.statusColor)
                .frame(width: 10, height: 10)
            Text(filter.statusText)
        }
    }
}
