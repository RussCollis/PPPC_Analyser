# PPPC Analyzer

A macOS tool that inspects a `.app` bundle and reports the Privacy, Preferences, Policy Control (PPPC) / TCC permissions it is likely to require — saving you the guesswork when building MDM configuration profiles.

Available two ways:

- **`pppc_analyzer.sh`** — a command-line script for terminal / scripted use
- **`PPPC_Analyser.xcodeproj`** — a native SwiftUI app with a drag-and-drop window, for everyone else

Both share the exact same detection rules, so results are identical either way.

## What it does

Given a path to any `.app`, PPPC Analyzer:

1. Reads the app's **Bundle ID**, **Code Signing Requirement**, and **Team ID**
2. Parses the app's **entitlements** and **Info.plist** privacy usage-description keys
3. Applies **well-known heuristics** for popular apps (Teams, Zoom, Slack, Chrome, Jamf, CrowdStrike, etc.)
4. Outputs a colour-coded list of TCC services categorised as **Required**, **Likely**, or **Possible**

The output gives you everything you need to pre-populate a PPPC payload in your MDM without needing to run the app interactively.

## GUI app

Open `PPPC_Analyser.xcodeproj` in Xcode and run it (`⌘R`). Then either:

- Drag a `.app` from Finder onto the drop zone, or
- Click **Choose App…** to pick one from `/Applications`

The results view shows the app's Bundle ID, Code Requirement, and Team ID alongside the same Required/Likely/Possible permission breakdown as the CLI. From there you can:

- **Copy Report** — copies a plain-text summary to the clipboard
- **Export Report…** — saves the summary to a `.txt` file
- **Create PPPC Profile…** — generates a ready-to-deploy `.mobileconfig` containing a `com.apple.TCC.configuration-profile-policy` payload, pre-filled with the app's Bundle ID and Code Requirement for each detected service
- **Analyze Another App** — resets back to the drop zone

Each detected permission has a checkbox so you control exactly what goes into the profile. **Required** and **Likely** permissions are checked by default; **Possible** permissions start unchecked since they're speculative, but can be opted in. A handful of services can't be expressed in a PPPC profile at all, so their checkbox is disabled and greyed out:

- **Apple Events / Automation** needs a specific target app (an `AEReceiver`) that the analyzer has no way to know — add it manually in your MDM
- **Location Services** and **Bluetooth** aren't manageable through the PPPC profile schema

The app will tell you exactly which permissions (if any) were left out of the saved profile so nothing is silently dropped.

The app runs unsandboxed (like the other local-inspection tools in this repo) so it can invoke `codesign` and read `Info.plist` for any app on disk without extra entitlements.

## CLI requirements

- macOS (uses `codesign`, `plutil`, `defaults` — all included with Xcode Command Line Tools)
- Bash 3.2+

## CLI usage

```bash
./pppc_analyzer.sh /path/to/App.app
```

### Examples

```bash
./pppc_analyzer.sh /Applications/Microsoft\ Teams.app
./pppc_analyzer.sh /Applications/zoom.us.app
./pppc_analyzer.sh /Applications/Slack.app
./pppc_analyzer.sh /Applications/Google\ Chrome.app
```

## Sample output

```
  PPPC Analyzer
  macOS Privacy & TCC Permission Inspector

  App:       Microsoft Teams
  Path:      /Applications/Microsoft Teams.app

  Bundle ID:  com.microsoft.teams2
  Code Req:   identifier "com.microsoft.teams2" and anchor apple generic ...
  Team ID:    UBF8T346G9

  ── Entitlements ───────────────────────────────────

  REQUIRED
  ●  Camera                       kTCCServiceCamera                 Video calls
  ●  Microphone                   kTCCServiceMicrophone             Audio calls
  ●  Screen Recording             kTCCServiceScreenCapture          Screen sharing

  LIKELY
  ●  Accessibility                kTCCServiceAccessibility          Keyboard shortcuts
  ●  Contacts                     kTCCServiceAddressBook            Contact search
```

## Permission levels

| Level | Meaning |
|-------|---------|
| **Required** | Entitlement or Info.plist key is present, or the app is well-known to need this permission to function |
| **Likely** | Strong indicator (entitlement, plist key, or app category) but may depend on features used |
| **Possible** | Declared in the bundle but may not be actively used |

## Using the output in your MDM

The **TCC service key** column (e.g. `kTCCServiceCamera`) maps directly to the `Services` dictionary in a macOS PPPC configuration profile. Pair it with the **Bundle ID** and **Code Requirement** shown at the top of the output.

Supported MDM platforms: Jamf Pro, Mosyle, Kandji, Addigy, VMware Workspace ONE, and any MDM that accepts a custom PPPC payload.

## License

[MIT](LICENSE)
