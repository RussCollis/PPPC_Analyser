//
//  AnalysisResultView.swift
//  PPPC_Analyser
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

private struct ProfileAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

struct AnalysisResultView: View {
    let analysis: PPPCAnalysis
    let onReset: () -> Void
    let onCopy: () -> Void
    let onExport: () -> Void

    @State private var justCopied = false
    @State private var profileAlert: ProfileAlert?
    @State private var selectedPermissionIDs: Set<UUID>

    init(analysis: PPPCAnalysis, onReset: @escaping () -> Void, onCopy: @escaping () -> Void, onExport: @escaping () -> Void) {
        self.analysis = analysis
        self.onReset = onReset
        self.onCopy = onCopy
        self.onExport = onExport
        // Required + Likely are checked by default, matching the tool's own confidence
        // levels; Possible starts unchecked since it's explicitly speculative. Anything
        // with no PPPC profile mapping (Apple Events, Location, Bluetooth) is never
        // selectable, so it's left out of the initial set regardless of tier.
        let defaultSelected = (analysis.required + analysis.likely)
            .filter { PPPCProfileBuilder.supportedServiceKey(for: $0.tccService) != nil }
            .map(\.id)
        _selectedPermissionIDs = State(initialValue: Set(defaultSelected))
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    appInfoCard

                    if analysis.totalCount == 0 {
                        Label("No PPPC permissions detected.", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.headline)
                            .padding(.top, 8)
                    } else {
                        Text("Check the permissions to include in a generated PPPC profile.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        PermissionSectionView(title: "Required", color: .red, permissions: analysis.required, selectedIDs: $selectedPermissionIDs)
                        PermissionSectionView(title: "Likely", color: .orange, permissions: analysis.likely, selectedIDs: $selectedPermissionIDs)
                        PermissionSectionView(title: "Possible", color: .green, permissions: analysis.possible, selectedIDs: $selectedPermissionIDs)
                    }
                }
                .padding(20)
            }

            Divider()

            HStack {
                Button("Analyze Another App", action: onReset)
                Spacer()
                Button(action: onExport) {
                    Label("Export Report…", systemImage: "square.and.arrow.down")
                }
                Button {
                    onCopy()
                    justCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        justCopied = false
                    }
                } label: {
                    Label(justCopied ? "Copied!" : "Copy Report", systemImage: justCopied ? "checkmark" : "doc.on.doc")
                }
                Button(action: createProfile) {
                    Label("Create PPPC Profile…", systemImage: "lock.doc")
                }
                .buttonStyle(.borderedProminent)
                .disabled(selectedPermissionIDs.isEmpty)
            }
            .padding(14)
        }
        .alert(item: $profileAlert) { alert in
            Alert(title: Text(alert.title), message: Text(alert.message), dismissButton: .default(Text("OK")))
        }
    }

    private func createProfile() {
        let allPermissions = analysis.required + analysis.likely + analysis.possible
        let selected = allPermissions.filter { selectedPermissionIDs.contains($0.id) }

        let result: PPPCProfileBuilder.BuildResult
        do {
            result = try PPPCProfileBuilder.build(from: analysis, selectedPermissions: selected)
        } catch {
            profileAlert = ProfileAlert(title: "Can't Create Profile", message: error.localizedDescription)
            return
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "mobileconfig") ?? .xml]
        panel.nameFieldStringValue = result.suggestedFilename
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            try result.profileData.write(to: url)
        } catch {
            profileAlert = ProfileAlert(title: "Couldn't Save Profile", message: error.localizedDescription)
            return
        }

        if result.skippedUnsupported.isEmpty {
            profileAlert = ProfileAlert(
                title: "Profile Saved",
                message: "\(result.includedCount) permission(s) written to \(url.lastPathComponent)."
            )
        } else {
            let notes = result.skippedUnsupported.map { "• \($0.permission.name): \($0.reason)" }.joined(separator: "\n")
            profileAlert = ProfileAlert(
                title: "Profile Saved — Review Needed",
                message: "\(result.includedCount) permission(s) written to \(url.lastPathComponent).\n\nAlways excluded, not supported by PPPC profiles:\n\n\(notes)"
            )
        }
    }

    private var appInfoCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(analysis.appName)
                .font(.title2)
                .fontWeight(.semibold)
            Text(analysis.appPath)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            Divider().padding(.vertical, 4)

            infoRow("Bundle ID", analysis.bundleID ?? "(could not determine)")
            infoRow("Code Req", analysis.codeRequirement ?? "(could not determine)")
            infoRow("Team ID", analysis.teamID ?? "(not found)")
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.secondary.opacity(0.08)))
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 70, alignment: .leading)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
        }
    }
}

private struct PermissionSectionView: View {
    let title: String
    let color: Color
    let permissions: [PPPCPermission]
    @Binding var selectedIDs: Set<UUID>

    var body: some View {
        if !permissions.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text(title.uppercased())
                    .font(.caption.weight(.bold))
                    .foregroundStyle(color)

                VStack(spacing: 0) {
                    ForEach(permissions) { permission in
                        PermissionRowView(color: color, permission: permission, selectedIDs: $selectedIDs)
                        if permission.id != permissions.last?.id {
                            Divider()
                        }
                    }
                }
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.secondary.opacity(0.06)))
            }
        }
    }
}

private struct PermissionRowView: View {
    let color: Color
    let permission: PPPCPermission
    @Binding var selectedIDs: Set<UUID>

    private var isSupported: Bool {
        PPPCProfileBuilder.supportedServiceKey(for: permission.tccService) != nil
    }

    private var isSelected: Binding<Bool> {
        Binding(
            get: { selectedIDs.contains(permission.id) },
            set: { newValue in
                if newValue {
                    selectedIDs.insert(permission.id)
                } else {
                    selectedIDs.remove(permission.id)
                }
            }
        )
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Toggle(isOn: isSupported ? isSelected : .constant(false)) {
                EmptyView()
            }
            .toggleStyle(.checkbox)
            .labelsHidden()
            .disabled(!isSupported)
            .padding(.top, 3)
            .help(isSupported ? "Include in the generated PPPC profile" : "Not supported by the PPPC profile schema")

            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
                .padding(.top, 5)

            VStack(alignment: .leading, spacing: 2) {
                Text(permission.name)
                    .font(.system(size: 13, weight: .semibold))
                Text(permission.tccService)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text(permission.reason)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                if !isSupported {
                    Text("Not supported in PPPC profiles")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                        .italic()
                }
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .opacity(isSupported ? 1.0 : 0.55)
    }
}
