//
//  ContentView.swift
//  PPPC_Analyser
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var analysis: PPPCAnalysis?
    @State private var isAnalyzing = false
    @State private var errorMessage: String?
    @State private var isTargeted = false

    private let service = PPPCAnalyzerService()

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if let analysis {
                AnalysisResultView(
                    analysis: analysis,
                    onReset: reset,
                    onCopy: { copyReport(analysis) },
                    onExport: { exportReport(analysis) }
                )
            } else {
                DropZoneView(
                    isAnalyzing: isAnalyzing,
                    errorMessage: errorMessage,
                    isTargeted: $isTargeted,
                    onDrop: handleDrop,
                    onBrowse: presentOpenPanel
                )
            }
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text("PPPC Analyzer")
                    .font(.title3)
                    .fontWeight(.bold)
                Text("macOS Privacy & TCC Permission Inspector")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(action: quitApp) {
                Label("Quit", systemImage: "power")
            }
            .help("Quit PPPC Analyzer")
        }
        .padding(16)
    }

    private func handleDrop(providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }) else {
            return false
        }
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
            guard let url else { return }
            DispatchQueue.main.async {
                beginAnalysis(url: url)
            }
        }
        return true
    }

    private func presentOpenPanel() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.application]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        if panel.runModal() == .OK, let url = panel.url {
            beginAnalysis(url: url)
        }
    }

    private func beginAnalysis(url: URL) {
        errorMessage = nil
        isAnalyzing = true
        Task.detached(priority: .userInitiated) {
            do {
                let result = try service.analyze(appURL: url)
                await MainActor.run {
                    self.analysis = result
                    self.isAnalyzing = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.isAnalyzing = false
                }
            }
        }
    }

    private func reset() {
        analysis = nil
        errorMessage = nil
    }

    private func copyReport(_ analysis: PPPCAnalysis) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(analysis.plainTextReport, forType: .string)
    }

    private func exportReport(_ analysis: PPPCAnalysis) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "\(analysis.appName)-PPPC-Report.txt"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? analysis.plainTextReport.write(to: url, atomically: true, encoding: .utf8)
    }

    private func quitApp() {
        NSApplication.shared.terminate(nil)
    }
}

#Preview {
    ContentView()
        .frame(width: 640, height: 520)
}
