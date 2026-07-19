//
//  DropZoneView.swift
//  PPPC_Analyser
//

import SwiftUI
import UniformTypeIdentifiers

struct DropZoneView: View {
    let isAnalyzing: Bool
    let errorMessage: String?
    @Binding var isTargeted: Bool
    let onDrop: ([NSItemProvider]) -> Bool
    let onBrowse: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                .foregroundStyle(isTargeted ? Color.accentColor : Color.secondary.opacity(0.4))
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(isTargeted ? Color.accentColor.opacity(0.08) : Color.clear)
                )
                .frame(maxWidth: 480, maxHeight: 260)
                .overlay {
                    VStack(spacing: 14) {
                        if isAnalyzing {
                            ProgressView()
                                .controlSize(.large)
                            Text("Analyzing…")
                                .font(.headline)
                                .foregroundStyle(.secondary)
                        } else {
                            Image(systemName: "app.badge.checkmark")
                                .font(.system(size: 40, weight: .light))
                                .foregroundStyle(isTargeted ? Color.accentColor : .secondary)
                            Text("Drag & drop a .app here")
                                .font(.headline)
                            Text("Drop any application bundle to inspect its PPPC / TCC requirements")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                            Button("Choose App…", action: onBrowse)
                                .buttonStyle(.bordered)
                                .padding(.top, 4)
                        }
                    }
                    .padding()
                }
                .onDrop(of: [.fileURL], isTargeted: $isTargeted, perform: onDrop)

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
            }

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
