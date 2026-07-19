//
//  PPPCAnalyzerService.swift
//  PPPC_Analyser
//
//  Native reimplementation of the pppc_analyzer.sh heuristics: reads a .app
//  bundle's code signature, entitlements, and Info.plist privacy keys, then
//  applies the same required/likely/possible detection rules.
//

import Foundation

nonisolated struct PPPCAnalyzerService {

    func analyze(appURL: URL) throws -> PPPCAnalysis {
        guard appURL.pathExtension.lowercased() == "app" else {
            throw PPPCAnalyzerError.notAnAppBundle
        }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: appURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw PPPCAnalyzerError.notFound
        }

        let appPath = appURL.path
        let appName = appURL.deletingPathExtension().lastPathComponent
        let infoPlistURL = appURL.appendingPathComponent("Contents/Info.plist")
        let infoPlist = readPlist(at: infoPlistURL)

        let bundleID = (infoPlist?["CFBundleIdentifier"] as? String) ?? codesignField(appPath: appPath, key: "Identifier")
        let teamID = codesignField(appPath: appPath, key: "TeamIdentifier")
        let codeRequirement = designatedRequirement(appPath: appPath)
        let entitlementKeys = entitlementKeys(appPath: appPath)
        let plistKeys = Set((infoPlist ?? [:]).keys.filter { $0.hasPrefix("NS") && $0.hasSuffix("UsageDescription") })

        var required: [PPPCPermission] = []
        var likely: [PPPCPermission] = []
        var possible: [PPPCPermission] = []

        func has(_ entitlement: String) -> Bool { entitlementKeys.contains(entitlement) }
        func hasPlist(_ key: String) -> Bool { plistKeys.contains(key) }
        func alreadyIn(_ name: String) -> Bool {
            required.contains { $0.name == name } || likely.contains { $0.name == name } || possible.contains { $0.name == name }
        }
        func add(_ level: PermissionLevel, _ name: String, _ tcc: String, _ reason: String) {
            let perm = PPPCPermission(name: name, tccService: tcc, reason: reason)
            switch level {
            case .required: required.append(perm)
            case .likely: likely.append(perm)
            case .possible: possible.append(perm)
            }
        }
        func addIfAbsent(_ level: PermissionLevel, _ name: String, _ tcc: String, _ reason: String) {
            guard !alreadyIn(name) else { return }
            add(level, name, tcc, reason)
        }

        // ── Entitlement / Info.plist based detection ──────────────────────
        if has("com.apple.security.device.camera") || hasPlist("NSCameraUsageDescription") {
            add(.required, "Camera", "kTCCServiceCamera", "Declares camera use")
        }
        if has("com.apple.security.device.microphone") || has("com.apple.security.device.audio-input") || hasPlist("NSMicrophoneUsageDescription") {
            add(.required, "Microphone", "kTCCServiceMicrophone", "Declares mic use")
        }
        if has("com.apple.security.screen-recording") {
            add(.required, "Screen Recording", "kTCCServiceScreenCapture", "Present")
        }
        if has("com.apple.security.files.all") || hasPlist("NSSystemAdministrationUsageDescription") {
            add(.required, "Full Disk Access", "kTCCServiceSystemPolicyAllFiles", "Declares full disk")
        }
        if has("com.apple.security.accessibility") {
            add(.required, "Accessibility", "kTCCServiceAccessibility", "Present")
        }
        if has("com.apple.security.automation.apple-events") || hasPlist("NSAppleEventsUsageDescription") {
            add(.required, "Apple Events / Automation", "kTCCServiceAppleEvents", "Declares Apple Events")
        }
        if has("com.apple.security.files.downloads.read-write") || has("com.apple.security.files.downloads.read-only") || hasPlist("NSDownloadsFolderUsageDescription") {
            add(.likely, "Downloads Folder", "kTCCServiceSystemPolicyDownloadsFolder", "Declares downloads access")
        }
        if has("com.apple.security.files.user-selected.read-write") || hasPlist("NSDocumentsFolderUsageDescription") {
            add(.likely, "Documents Folder", "kTCCServiceSystemPolicyDocumentsFolder", "Declares documents")
        }
        if hasPlist("NSDesktopFolderUsageDescription") {
            add(.likely, "Desktop Folder", "kTCCServiceSystemPolicyDesktopFolder", "Info.plist declares desktop access")
        }
        if has("com.apple.security.personal-information.addressbook") || hasPlist("NSContactsUsageDescription") {
            add(.likely, "Contacts", "kTCCServiceAddressBook", "Declares contacts")
        }
        if has("com.apple.security.personal-information.calendars") || hasPlist("NSCalendarsUsageDescription") {
            add(.likely, "Calendar", "kTCCServiceCalendars", "Declares calendar")
        }
        if has("com.apple.security.personal-information.reminders") || hasPlist("NSRemindersUsageDescription") {
            add(.possible, "Reminders", "kTCCServiceReminders", "Plist declares reminders")
        }
        if has("com.apple.security.personal-information.location") || hasPlist("NSLocationUsageDescription") || hasPlist("NSLocationWhenInUseUsageDescription") {
            add(.possible, "Location Services", "kTCCServiceLocation", "Declares location")
        }
        if has("com.apple.security.personal-information.photos-library") || hasPlist("NSPhotoLibraryUsageDescription") {
            add(.possible, "Photos Library", "kTCCServicePhotos", "Declares photo library")
        }
        if hasPlist("NSBluetoothAlwaysUsageDescription") || hasPlist("NSBluetoothPeripheralUsageDescription") {
            add(.possible, "Bluetooth", "kTCCServiceBluetooth", "Plist declares Bluetooth")
        }

        // ── Well-known app heuristics ───────────────────────────────────
        let haystack = "\((bundleID ?? "").lowercased()) \(appName.lowercased())"
        func matches(_ pattern: String) -> Bool {
            haystack.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
        }

        if matches("teams") {
            addIfAbsent(.required, "Camera", "kTCCServiceCamera", "Video calls")
            addIfAbsent(.required, "Microphone", "kTCCServiceMicrophone", "Audio calls")
            addIfAbsent(.required, "Screen Recording", "kTCCServiceScreenCapture", "Screen sharing")
            addIfAbsent(.likely, "Accessibility", "kTCCServiceAccessibility", "Keyboard shortcuts")
            addIfAbsent(.likely, "Contacts", "kTCCServiceAddressBook", "Contact search")
        }
        if matches("zoom") {
            addIfAbsent(.required, "Camera", "kTCCServiceCamera", "Video conferencing")
            addIfAbsent(.required, "Microphone", "kTCCServiceMicrophone", "Audio conferencing")
            addIfAbsent(.required, "Screen Recording", "kTCCServiceScreenCapture", "Screen sharing")
            addIfAbsent(.required, "Accessibility", "kTCCServiceAccessibility", "Meeting controls")
        }
        if matches("slack") {
            addIfAbsent(.likely, "Camera", "kTCCServiceCamera", "Huddles & video")
            addIfAbsent(.likely, "Microphone", "kTCCServiceMicrophone", "Huddles & voice messages")
            addIfAbsent(.likely, "Screen Recording", "kTCCServiceScreenCapture", "Screen sharing")
            addIfAbsent(.likely, "Downloads Folder", "kTCCServiceSystemPolicyDownloadsFolder", "File downloads")
        }
        if matches("chrome|firefox|brave|edge") {
            addIfAbsent(.likely, "Camera", "kTCCServiceCamera", "Web camera API")
            addIfAbsent(.likely, "Microphone", "kTCCServiceMicrophone", "Web mic API")
            addIfAbsent(.likely, "Screen Recording", "kTCCServiceScreenCapture", "Screen sharing via browser")
            addIfAbsent(.required, "Downloads Folder", "kTCCServiceSystemPolicyDownloadsFolder", "Browser downloads")
        }
        if matches("jamf|mosyle|kandji|addigy|workspace\\.one") {
            addIfAbsent(.required, "Full Disk Access", "kTCCServiceSystemPolicyAllFiles", "MDM management")
            addIfAbsent(.required, "Accessibility", "kTCCServiceAccessibility", "Remote management")
        }
        if matches("falcon|crowdstrike|sentinelone|cbdefense|carbonblack|cylance") {
            addIfAbsent(.required, "Full Disk Access", "kTCCServiceSystemPolicyAllFiles", "Security scanning")
        }

        return PPPCAnalysis(
            appName: appName,
            appPath: appPath,
            bundleID: bundleID,
            codeRequirement: codeRequirement,
            teamID: teamID,
            required: required,
            likely: likely,
            possible: possible
        )
    }

    // MARK: - Plist reading

    private func readPlist(at url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    // MARK: - codesign helpers

    /// Runs a process and returns stdout with stderr merged in (matches the CLI's `2>&1` usage).
    private func runMerged(_ launchPath: String, _ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return ""
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Runs a process and returns stdout only, discarding stderr.
    private func runStdoutOnly(_ launchPath: String, _ arguments: [String]) -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return Data()
        }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return data
    }

    private func codesignField(appPath: String, key: String) -> String? {
        let output = runMerged("/usr/bin/codesign", ["-dvvv", appPath])
        for line in output.split(separator: "\n") {
            if line.hasPrefix("\(key)=") {
                return String(line.dropFirst(key.count + 1))
            }
        }
        return nil
    }

    private func designatedRequirement(appPath: String) -> String? {
        let output = runMerged("/usr/bin/codesign", ["-dr", "-", appPath])
        let prefix = "designated => "
        for line in output.split(separator: "\n", omittingEmptySubsequences: false) {
            if line.hasPrefix(prefix) {
                return String(line.dropFirst(prefix.count))
            }
        }
        return nil
    }

    private func entitlementKeys(appPath: String) -> Set<String> {
        let data = runStdoutOnly("/usr/bin/codesign", ["-d", "--entitlements", "-", "--xml", appPath])
        guard !data.isEmpty,
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return []
        }
        return Set(plist.keys)
    }
}
