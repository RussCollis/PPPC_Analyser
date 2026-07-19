//
//  PPPCProfileBuilder.swift
//  PPPC_Analyser
//
//  Builds a .mobileconfig containing a com.apple.TCC.configuration-profile-policy
//  payload from a set of user-selected permissions, ready to import into an MDM
//  or install locally.
//

import Foundation

enum PPPCProfileError: LocalizedError {
    case missingIdentity
    case nothingToInclude

    var errorDescription: String? {
        switch self {
        case .missingIdentity:
            return "This app's Bundle ID or Code Requirement couldn't be determined, so a valid PPPC profile can't be generated."
        case .nothingToInclude:
            return "None of the selected permissions can be expressed in a PPPC configuration profile."
        }
    }
}

enum PPPCProfileBuilder {

    struct UnsupportedPermission {
        let permission: PPPCPermission
        let reason: String
    }

    struct BuildResult {
        let profileData: Data
        let suggestedFilename: String
        let includedCount: Int
        /// All permissions detected on the app (regardless of selection) that can never
        /// be expressed in a PPPC profile, so the caller can explain why they're missing.
        let skippedUnsupported: [UnsupportedPermission]
    }

    /// Maps our internal TCC service constant to the public PPPC profile "Services" key.
    private static let serviceKeyMap: [String: String] = [
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceScreenCapture": "ScreenCapture",
        "kTCCServiceSystemPolicyAllFiles": "SystemPolicyAllFiles",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceSystemPolicyDownloadsFolder": "SystemPolicyDownloadsFolder",
        "kTCCServiceSystemPolicyDocumentsFolder": "SystemPolicyDocumentsFolder",
        "kTCCServiceSystemPolicyDesktopFolder": "SystemPolicyDesktopFolder",
        "kTCCServiceAddressBook": "AddressBook",
        "kTCCServiceCalendars": "Calendar",
        "kTCCServiceReminders": "Reminders",
        "kTCCServicePhotos": "Photos",
    ]

    private static let unsupportedReasons: [String: String] = [
        "kTCCServiceAppleEvents": "Apple Events needs a specific target app (an AEReceiver) — add this service manually in your MDM.",
        "kTCCServiceLocation": "Location Services isn't manageable through a PPPC configuration profile.",
        "kTCCServiceBluetooth": "Bluetooth isn't manageable through a PPPC configuration profile.",
    ]

    /// The PPPC profile "Services" key for a TCC service constant, or nil if it can't be expressed in a profile.
    static func supportedServiceKey(for tccService: String) -> String? {
        serviceKeyMap[tccService]
    }

    static func unsupportedReason(for tccService: String) -> String? {
        unsupportedReasons[tccService]
    }

    static func build(from analysis: PPPCAnalysis, selectedPermissions: [PPPCPermission], organization: String = "MDM Magic") throws -> BuildResult {
        guard let bundleID = analysis.bundleID, !bundleID.isEmpty,
              let codeRequirement = analysis.codeRequirement, !codeRequirement.isEmpty else {
            throw PPPCProfileError.missingIdentity
        }

        var servicesDict: [String: [[String: Any]]] = [:]
        var includedCount = 0

        for permission in selectedPermissions {
            guard let serviceKey = serviceKeyMap[permission.tccService] else { continue }
            let entry: [String: Any] = [
                "Identifier": bundleID,
                "IdentifierType": "bundleID",
                "CodeRequirement": codeRequirement,
                "Allowed": true,
                "Comment": "\(permission.name) — \(permission.reason)",
            ]
            servicesDict[serviceKey, default: []].append(entry)
            includedCount += 1
        }

        guard includedCount > 0 else {
            throw PPPCProfileError.nothingToInclude
        }

        let allDetected = analysis.required + analysis.likely + analysis.possible
        let skippedUnsupported: [UnsupportedPermission] = allDetected.compactMap { permission in
            guard serviceKeyMap[permission.tccService] == nil else { return nil }
            let reason = unsupportedReasons[permission.tccService] ?? "Not supported by the PPPC profile schema."
            return UnsupportedPermission(permission: permission, reason: reason)
        }

        let tccPayload: [String: Any] = [
            "PayloadType": "com.apple.TCC.configuration-profile-policy",
            "PayloadVersion": 1,
            "PayloadIdentifier": "au.mdmmagic.pppc.\(bundleID).tcc",
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": "Privacy Preferences Policy Control",
            "PayloadEnabled": true,
            "Services": servicesDict,
        ]

        let profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": "au.mdmmagic.pppc.\(bundleID)",
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": "\(analysis.appName) — PPPC",
            "PayloadDescription": "Privacy Preferences Policy Control profile generated by PPPC Analyzer for \(analysis.appName) (\(bundleID)).",
            "PayloadOrganization": organization,
            "PayloadScope": "System",
            "PayloadContent": [tccPayload],
        ]

        let data = try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
        return BuildResult(
            profileData: data,
            suggestedFilename: "\(analysis.appName)-PPPC.mobileconfig",
            includedCount: includedCount,
            skippedUnsupported: skippedUnsupported
        )
    }
}
