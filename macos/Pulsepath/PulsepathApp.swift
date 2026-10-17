import SwiftUI

@main
struct PulsepathApp: App {
    @StateObject private var filter = FilterController()

    var body: some Scene {
        WindowGroup("Pulsepath Observer") {
            ContentView(filter: filter)
                .frame(minWidth: 520, minHeight: 420)
        }
    }
}
