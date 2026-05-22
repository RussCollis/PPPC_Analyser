# PPPC Analyzer

A macOS shell script that inspects a `.app` bundle and reports the Privacy, Preferences, Policy Control (PPPC) / TCC permissions it is likely to require — saving you the guesswork when building MDM configuration profiles.

## What it does

Given a path to any `.app`, PPPC Analyzer:

1. Reads the app's **Bundle ID**, **Code Signing Requirement**, and **Team ID**
2. Parses the app's **entitlements** and **Info.plist** privacy usage-description keys
3. Applies **well-known heuristics** for popular apps (Teams, Zoom, Slack, Chrome, Jamf, CrowdStrike, etc.)
4. Outputs a colour-coded list of TCC services categorised as **Required**, **Likely**, or **Possible**

The output gives you everything you need to pre-populate a PPPC payload in your MDM without needing to run the app interactively.

## Requirements

- macOS (uses `codesign`, `plutil`, `defaults` — all included with Xcode Command Line Tools)
- Bash 3.2+

## Usage

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
