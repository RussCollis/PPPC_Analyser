//
//  PPPCModels.swift
//  PPPC_Analyser
//

import Foundation

enum PermissionLevel {
    case required
    case likely
    case possible
}

struct PPPCPermission: Identifiable {
    let id = UUID()
    let name: String
    let tccService: String
    let reason: String
}

struct PPPCAnalysis {
    let appName: String
    let appPath: String
    let bundleID: String?
    let codeRequirement: String?
    let teamID: String?
    let required: [PPPCPermission]
    let likely: [PPPCPermission]
    let possible: [PPPCPermission]

    var totalCount: Int { required.count + likely.count + possible.count }

    /// Plain-text rendering matching the CLI tool's output, for copying into MDM configs.
    var plainTextReport: String {
        var lines: [String] = []
        lines.append("PPPC Analyzer — macOS Privacy & TCC Permission Inspector")
        lines.append("")
        lines.append("App:        \(appName)")
        lines.append("Path:       \(appPath)")
        lines.append("Bundle ID:  \(bundleID ?? "(could not determine)")")
        lines.append("Code Req:   \(codeRequirement ?? "(could not determine)")")
        lines.append("Team ID:    \(teamID ?? "(not found)")")
        lines.append("")

        if totalCount == 0 {
            lines.append("No PPPC permissions detected.")
        } else {
            func section(_ title: String, _ perms: [PPPCPermission]) {
                guard !perms.isEmpty else { return }
                lines.append(title)
                for p in perms {
                    lines.append("  •  \(p.name)  \(p.tccService)  \(p.reason)")
                }
                lines.append("")
            }
            section("REQUIRED", required)
            section("LIKELY", likely)
            section("POSSIBLE", possible)
        }

        return lines.joined(separator: "\n")
    }
}

enum PPPCAnalyzerError: LocalizedError {
    case notAnAppBundle
    case notFound

    var errorDescription: String? {
        switch self {
        case .notAnAppBundle:
            return "That doesn't look like a .app bundle."
        case .notFound:
            return "The app couldn't be found at that location."
        }
    }
}
