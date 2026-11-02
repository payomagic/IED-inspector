# IED Inspector 0.7.2

Read-only IEC 61850 inspection tool: MMS, GOOSE, Sampled Values, SCD validation, comparison, reports and an IED simulator. Runs in the browser and is served by a small local Python program. Nothing to install apart from Python.


[![PyPI](https://img.shields.io/pypi/v/ied-inspector)](https://pypi.org/project/ied-inspector/) ![Python](https://img.shields.io/pypi/pyversions/ied-inspector) ![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Install and start:

    pip install "ied-inspector[gui]"     # with the desktop window (pywebview)
    pip install ied-inspector            # browser only, no dependencies at all
    ied-inspector

At start a small dialog asks whether to open the tool as a **desktop window** or in the **web browser**. Both show the same interface. "Remember my choice" skips the dialog next time; you can change this in Settings, or start with `--ask`.

| Option | Effect |
|---|---|
| `--gui` | desktop window (Windows: Edge WebView2, built into Windows 10/11; Linux: GTK + WebKit2, e.g. `apt install python3-gi gir1.2-webkit2-4.1`) |
| `--web` | web browser |
| `--ask` | show the start dialog again |
| `--no-browser` | web server only, no window |

If the desktop window cannot be opened (no WebView2, no display, pywebview missing), the tool shows the reason, writes details to `ied_inspector.log` next to the program, and opens the browser instead. `IEDInspector.exe --diag` (or `ied-inspector --diag`) checks everything the desktop window needs: pywebview, pythonnet, the WebView2 DLLs, the installed WebView2 runtime and the window icon. If the window icon is ever the problem, start with the environment variable `IED_INSPECTOR_NO_ICON=1`.

## Start

| | |
|---|---|
| Windows | double-click `start_windows.bat`, or `py run.py` |
| Linux   | `./start_linux.sh` (uses sudo for raw sockets), or `sudo python3 run.py` |

The browser opens at http://127.0.0.1:8061. Options: `--port 8061`, `--scd file.scd` (load at start), `--no-browser`, `--host 0.0.0.0` (expose the UI on the network; there is no login).

Requirements: Python 3.9 or newer, standard library only. A portable Python (for example the Windows "embeddable" zip) also works, so the tool can live on a USB stick.

| Feature | Windows | Linux |
|---|---|---|
| MMS client, SCD, pcap files, reports | works out of the box | works out of the box |
| Live GOOSE/SV capture, simulator publishing | needs [Npcap](https://npcap.com) | root or `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))` |
| Simulator MMS server on port 102 | works | root, or use another port |

## What it does

- **Connect (MMS)**: reads identity, every GOOSE and SV control block (VLAN ID, priority, APPID, destination MAC, ConfRev, GoID, DataSet, GoEna) and the dataset values. You can choose the source interface, and read all IEDs of the SCD in one click.
- **Network**: live capture on a selected interface, or analysis of a .pcap/.pcapng file. It detects GOOSE timeouts against TAL, the TEST flag, the simulation bit, NdsCom, stNum/sqNum errors and VLAN changes. For SV it reports frames per second and smpCnt gaps. If all frames arrive untagged, it warns about switch port mode or NIC VLAN offload. A live capture can be saved as .pcap.
- **SCD file**: loads .scd/.cid/.icd/.iid files and validates them. Checks cover the VLAN-ID range and 3-digit hex format, APPID and MAC ranges, duplicate APPID/MAC/IP/GoID, missing GSE/SMV addresses, missing or empty datasets, FCDAs that don't exist in the data model, and subscriptions to unknown IEDs or control blocks. A green or red LED shows MMS reachability for each IED.
- **Device view** (Compare → Device): for every IED, the VLANs it uses are shown as chips (e.g. "VLAN 706 · sends 1 · receives 3"), plus the list of VLANs its switch port needs. Below that are two lists:
  - **Publishes**: its own control blocks.
  - **Receives**: every incoming GOOSE/SV stream, with VLAN, publisher and IP, APPID, the signals it uses (from the SCD ExtRefs), status on the network, and reception confirmed over MMS (LGOS/LSVS or vendor diagnostics). Also exported as CSV ("VLANs per device") and in the HTML comparison report.
- **Compare**: shows SCD vs device (MMS) vs network for every field. The view can be organized by device, VLAN, IP or signal. A VLAN matrix shows, per device, which VLANs it publishes and subscribes to (the switch-port VLAN list). Subscribers are marked when the publisher's real VLAN differs from the SCD. If the SCD is loaded after reading or capturing, everything is re-validated automatically.
- **Subscriber reception (VLAN path check over MMS)**: the tool reads every **LGOS** (GOOSE) and **LSVS** (SV) subscription-supervision node it finds on a connected IED (IEC 61850-7-4 Ed2). It reports St (receiving yes/no), SimSt, LastStNum and expected/received ConfRev, and links each one to the publisher's control block. If a subscriber does not receive a stream that is published on VLAN X, the subscriber is marked red with "check that VLAN X is allowed on the subscriber's switch port and on all trunks". This proves the VLAN path end to end without a laptop on every switch. IEDs without LGOS/LSVS (Ed1 or vendor-specific supervision) are listed as "cannot be confirmed over MMS".
- **ABB vendor supervision**: for devices without LGOS/LSVS the app reads ABB's own receive diagnostics.
  - *615 / 620 series* (REF615, RED620, RET620 …): `LD0.GSEGGIO1`. `Alm` is the receiver alarm, and IntIn1…IntIn10 are counters for received messages, time-outs, ConfRev mismatches, test frames, Needs Commissioning and dataset errors. This covers all subscriptions of the IED together, so the app shows which subscribed streams and VLANs to check.
  - *670 series* (RED670 …): the GOOSE receive function blocks (GOOSEBINRCV, GOOSEDPRCV, GOOSESPRCV …) and their DATAVALID / COMMVALID / TEST outputs. These are found by name because the MMS mapping depends on the configuration.
  - Other LNs that look GOOSE-related are listed as "candidates".
- **ABB CI868 (AC 800M)**: recognised from the SCD (type, name or description containing CI868 / AC 800M) or from the MMS identity.
  - It is read over MMS like any IED: GOOSE control blocks, datasets, LGOS if configured, and the data-model export.
  - If its MMS server does not answer, the tool checks whether the host is up (TCP 102 refused, ping, or its GOOSE alive on the network). In that case it shows an amber LED with a hint about the MMS server / CID download, instead of the red "not reachable".
  - SCD check of the module load against the CI868A data sheet: at most 120 IEDs via GOOSE, 40 IEDs as MMS report client (from ReportControl ClientLN), and 40 IEDs when both are combined.
  - The demo SCD contains a CI868 (PMS_CI868) that publishes a load-shedding GOOSE, subscribes to PROT_Q01 and CTRL_Q01, and receives reports from PROT_Q01.
- **Reachability for all devices**: the LED is green when MMS answers, amber when the host is up but MMS does not answer, and red when there is no answer at all.
- **Test and simulation mode** (MMS and network): the TEST badge appears when `LLN0.Mod/Beh` reads test **or** when the device's own GOOSE frames carry the TEST flag on the network. It says which of the two detected it, and flags any mismatch. "SIM FRAMES" marks devices that publish with the simulation bit.
- **Test and simulation mode over MMS**: for every logical device the tool reads `LLN0.Mod` / `LLN0.Beh` (on, blocked, test, test/blocked, off) and `LPHD.Sim`. Simulation mode means the IED accepts simulated GOOSE/SV instead of the real ones. Devices with test or simulation mode active get a **TEST** / **SIMULATION** badge on their tile and in the device view, plus a warning. Each subscription additionally shows `SimSt` from LGOS/LSVS. The simulator's TEST and simulation checkboxes set these values too.
- **Data model export** (Connect → Data model): every MMS variable name of the IED as a text file. Useful for finding vendor-specific diagnostics.
- **Simulator**: any IED of the SCD can be simulated with a read-only MMS server, GOOSE publishing (with retransmission) and 9-2 sampled values (sine waves). You can change signal values, which triggers GOOSE, and toggle the TEST and simulation bits. A simulated IED that has LGOS/LSVS nodes really listens on the interface and updates them. Its "VLANs allowed on this IED's switch port" field emulates a port that is missing a VLAN. For testing the checks you can stop a stream to provoke a timeout, or override its VLAN to provoke a mismatch. Use one IP per simulated IED: 127.0.0.x works locally, or add secondary IPs to the network adapter.
- **Reports**: comparison report (HTML, CSV for control blocks, signals and findings, JSON), a per-connection report (HTML, text, JSON), and a session summary of everything done since the program started.

## Read-only by design

The built-in MMS client contains only Initiate, Identify, GetNameList, GetVariableAccessAttributes, Read, GetNamedVariableListAttributes and Conclude. No write service is implemented. The simulator's MMS server answers every write request with "access denied".

## MMS stacks

The built-in stack is our own implementation and contains no third-party code. As an alternative, you can use libiec61850 by MZ Automation (GPLv3 or commercial licence). It is **not shipped** with this tool. To use it:

1. Download or build it from https://github.com/mz-automation/libiec61850. To build the shared library: `mkdir build && cd build && cmake .. && cmake --build . --config Release`.
2. Settings → MMS stack → enter the path of `iec61850.dll` / `libiec61850.so` → Test library.
3. Choose the stack per connection on the Connect tab, or set it as the default.

## Try it without hardware

1. SCD file tab → load `ied_inspector/examples/demo_substation.scd (or the "Load demo SCD" button)`. It contains 4 IEDs and deliberately includes a few SCD errors.
2. Simulator tab → start PROT_Q01 on 127.0.0.11, CTRL_Q01 on 127.0.0.21 and MU_Q01 on 127.0.0.31, each publishing on the loopback interface (Linux: `lo`; Windows: "Adapter for loopback traffic capture" from Npcap).
3. Network tab → capture on the same interface.
4. Connect tab → read 127.0.0.11, .21 and .31.
5. Simulator → set an override VLAN on GCB_POS. On the Compare tab, the publisher and its subscriber CTRL_Q01 turn red.
6. Simulator → CTRL_Q01 → enter `10` in "VLANs allowed on this IED's switch port". Then read 127.0.0.21 again on the Connect tab. LGOS2 now reports that GCB_POS (VLAN 20) is not received, and CTRL_Q01 turns red.

## Notes and limits

- Settings are stored in `~/.ied_inspector.json`.
- The simulator does not simulate report control blocks or controls. SV timing is best effort; Windows timer resolution makes it bursty.
- On Windows the simulator uses a fixed source MAC (00-1A-2B-3C-4D-5E).
- Single-file Windows exe: see "Build IEDInspector.exe" below.
- Tested against libiec61850 1.6.2 (server and client) and the built-in simulator. Not yet tested against vendor IEDs; please report any device that behaves differently.

## Build IEDInspector.exe (runs on Windows PCs without Python)

1. On **one** Windows PC with Python 3.9+ (python.org installer, "Add python.exe to PATH" ticked) and internet access, double-click `build_windows_exe.bat`.
2. The exe gets the icon from `assets\IEDInspector.ico` (sizes 16–256 px; source drawings `icon.svg` and `icon_small.svg` in the same folder). It creates a private build environment (`.build-venv`), installs PyInstaller and builds `dist\IEDInspector.exe` (about 10 MB). The web interface and the demo SCD are inside the exe.
3. Copy `IEDInspector.exe` to any Windows 10/11 PC and double-click it. The browser opens http://127.0.0.1:8061. Keep the console window open while you work, and close it to quit. Run `IEDInspector.exe --help` for options.

Notes for the target PC:
- MMS, SCD, pcap analysis, reports and the simulator's MMS server need nothing extra.
- Live capture and GOOSE/SV publishing need the Npcap driver (https://npcap.com). If Npcap was installed with "Restrict Npcap driver's access to Administrators only", start the exe with "Run as administrator".
- Windows Firewall may ask about network access the first time the simulator's MMS server listens. Allow it on private networks only if other PCs should reach the simulator.
- One-file executables unpack to a temporary folder at start, so the first start takes a few seconds. Some antivirus products flag unsigned PyInstaller executables; if that happens, sign the exe with a code-signing certificate or ask your IT department to whitelist it.

## Disclaimer

IED Inspector is an independent open-source project. It is not affiliated with, endorsed by or supported by ABB, OMICRON, MZ Automation or any other vendor. Product names such as ABB, Relion, REF615, RED670, CI868, AC 800M, IEDScout and libiec61850 are trademarks of their respective owners and are used here only to describe compatibility.

Vendor-specific behaviour (ABB GSEGGIO1 counters, 670-series receive blocks, CI868 module limits) is based on public manuals and data sheets and has not been verified on every firmware version. The software is provided "as is" (see LICENSE). Use it on substation networks at your own responsibility. It is read-only by design, but capture and the simulator send and receive real network traffic.

## Security

- The web interface listens on 127.0.0.1 only, unless you start it with `--host`. In desktop mode it uses a random port.
- **Cross-site request protection:** every API and download request must carry a random per-session token. The token is only written into the page this server delivers, so other web sites you visit cannot use the API: they cannot start the simulator, capture traffic or read data. Requests with a foreign `Origin`, `Sec-Fetch-Site: cross-site` or an unknown `Host` header (DNS rebinding) are refused.
- There is no login, so do not expose it to untrusted networks with `--host`.
- Report security problems privately to the author instead of in a public issue.

## License

MIT © 2026 Pavel Dvořák
