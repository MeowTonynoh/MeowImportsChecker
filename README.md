# Meow Imports Checker

Forensic analysis tool for Minecraft anti-cheat staff. Scans files for cheat client signatures, suspicious behavioral patterns, PE imports, obfuscation artifacts, and injection techniques — with integrated VirusTotal verification.


## ⚠️ Antivirus Notice

This tool **will be flagged as suspicious by some antiviruses**. This is a false positive.

- The tool extracts strings from binaries and reads PE import tables — behaviors that overlap with generic AV heuristics
- The source code is fully available in this repository for anyone to verify
- **The tool does NOT upload any data** — all analysis is 100% local
- **The tool does NOT modify any file** — read-only at every step


## Usage

Download and run the `.exe` as **Administrator**.  
Admin rights are required to access certain file metadata and Authenticode signatures.

At startup you'll be presented with four input modes:


## Input Modes

### `[1]` Single File

Provide the path to a single file to analyze.

```
PATH: C:\Users\you\Downloads\suspicioustool.exe
```

Works on any file type — executables, libraries, archives, scripts, and generic binaries.


### `[2]` Folder Scan

Provide a folder path. Every file inside will be enumerated and analyzed.

```
FOLDER PATH: C:\Users\you\Downloads\mods
```

---

### `[3]` Multiple Files

Provide multiple paths separated by commas. Invalid or missing paths are skipped with a warning, valid ones are queued for analysis.

```
PATHS: C:\file1.exe, C:\file2.jar, C:\file3.bat
```


### `[4]` Path Parser — `paths.txt` mode

The most powerful mode, designed for bulk investigation. Feed the tool a plain text file containing a list of file paths — for example an export from [Everything](https://www.voidtools.com/) or any custom file system listing — and it will handle everything automatically.

**Input detection**  
If no path is provided, the tool auto-detects `paths.txt`, `search results.txt`, or `p.txt` in the current directory.

**Smart filtering**  
Before any analysis starts, the tool filters the list aggressively to avoid wasting time:
- Trusted system paths are whitelisted automatically — Windows directories, Program Files, and known vendors (NVIDIA, Steam, OBS, Battle.net, Epic Games, Riot Games, Ubisoft, etc.) are skipped entirely
- Non-PE files are discarded
- An optional **DLL-only mode** (`Scan DLLs only? Y/N`) lets you focus exclusively on injected libraries

**Deleted path tracking**  
Files that appear in the list but no longer exist on disk are separately reported. A long list of missing files — especially in temp folders or AppData — can be a strong indicator that the suspect ran a cleanup routine before the inspection.

**Two-stage pipeline**  
The tool first runs a fast pre-scan across all valid paths in parallel, tagging each file with its initial threat flags. Only files that fail the pre-scan are promoted to the full deep analysis — keeping things fast even on large exports with hundreds of files.

**Cheat-signed files skip the whitelist**  
Even if a file sits in a normally trusted path, if it carries a known cheat signature it will still be flagged and deep-scanned. A signed system path is not a free pass.


## How Analysis Works

For every file, the tool runs a **multi-layer forensic pipeline**:


### Phase 1 — Authenticode Signature

Verifies whether the file carries a valid Windows digital signature via Authenticode.  
Trusted system paths are automatically whitelisted without further checking.  
Signed files with no cheat hits are skipped immediately — no unnecessary deep scan.


### Phase 2 — String Extraction

Strings are extracted from the binary using **three independent passes**:

**ASCII pass** — reads all printable ASCII sequences (minimum 4 characters)

**Unicode / UTF-16 pass** — same threshold on 2-byte encoded strings

**.NET Metadata pass** — if the binary is a .NET assembly, the tool manually parses the CLR metadata to extract the `#Strings` heap (type and method names) and the `#US` heap (user string literals). This recovers internal identifiers that are completely invisible to normal string extraction and survive most obfuscators.

For archive formats the archive is decompressed in memory. Each relevant entry — class files, configs, manifests, scripts — is scanned individually.


### Phase 3 — PE Import Table

The tool manually walks the PE Import Directory to recover the full list of imported DLL functions — no external tools required.

This catches API-level indicators regardless of string obfuscation: `WriteProcessMemory`, `CreateRemoteThread`, `VirtualAllocEx`, `OpenProcess`, `SetWindowsHookEx`, NT-level syscall wrappers, and more.


### Phase 4 — Cheat Signature Matching `[CS]`

Extracted content is matched against a database of **known cheat client signatures** — class names, resource identifiers, internal string literals, PDB paths, and namespace patterns unique to specific clients.

The full list of detected clients:

> OPAutoClicker · VroomClicker · MangoClicker · Koid · Void Lite · LilithClicker · DoggoClicker · COFFE LITE · 1337Clicker · AionClicker · AuriumClicker · Null · GS AutoClicker · Penguin Switcher · 198Macros · DogShitClicker · OzixClicker · DopeClicker · Vape Lite · Vape V4 · BlatantClicker · Crim · Fox Clicker · Axenta Clicker · Kaos Client · Luvsy Clicker · Obscure Client · Diff PE Injection · Pixel Clicker · Hasherezade Process Ghosting · Rappi Clicker · Slinky Library DLL · Slinky Hook DLL · Lily SlinkyLoader · Hydrogen Client · Sukki Clicker · Vega Clicker · Wok Clicker · tylow · tylow (Updated) · Crown Cheat · Epic Clicker · Icetea · Doomsday Client · Prestige Injector

A `[CS]` hit means a string **exclusive** to one of these clients was found embedded in the file. The exact client name is shown in the output.


### Phase 5 — YARA-style Rule Engine

The extracted content is tested against several independent rule sets. Each targets a specific threat category:

| Tag | Category | What it catches |
|-----|----------|----------------|
| `A` | Autoclicker APIs | `mouse_event`, `SendInput`, `TrackMouseEvent`, CPS references, jitter/butterfly click, blockhit, triggerbot patterns |
| `sA` | Known-bad identifiers | Strings and identifiers exclusive to specific known tools and loaders |
| `B` | Packers & Protectors | VMProtect, Themida, UPX, Enigma Protector, ASPack, PECompact, Obsidium, SafeEngine… |
| `C` | .NET Obfuscators | ConfuserEx, Eazfuscator, BabelObfuscator, SmartAssembly, .NET Reactor, Agile.NET, ILProtector… |
| `D` | Suspicious filenames | File names matching known autoclicker and cheat tools |
| `E` | Python runtimes | PyInstaller, Nuitka, cx_Freeze, py2exe — cheats compiled as Python executables |
| `F` | Packer section names | `.vmp0/.vmp1/.vmp2`, `.themida`, `UPX!`, `.mpress1`, `.petite`, `.enigma1`… |
| `G` | Injection indicators | NT-level APIs, manual mapping strings, `CreateRemoteThread`, process hollowing output, reflective DLL loading |
| `I` | Clicker behavior | CPS sliders, jitter/butterfly click, reach macros, crystal/anchor automation, totem macros, anti-AFK, prefetch clearing, self-destruct routines |
| `P` | Process overwrite | Loader output strings from process hollowing / overwrite injectors |


### Phase 6 — Suspicious String Detection

Beyond cheat-specific signatures, the tool scans for a wide set of **behavioral strings** that indicate malicious or cheat-related functionality. Some examples of what gets flagged:

**Mouse input & clicking**
`mouse_event` · `GetAsyncKeyState` · `GetAsyncKey` · `MouseEventHandler` · `MouseClickDelay` · `MOUSEEVENTF_LEFTDOWN` · `MOUSEEVENTF_RIGHTDOWN` · `MOUSEEVENTF_MOVE` · `TrackMouseEvent` · `Send Input` · `Invoke-Click -Button "Left"` · `Invoke-Click -Button "Right"` · `X1 mouse` · `X2 mouse` · `MOUSE4` · `MOUSE5`

**CPS & clicker logic**
`cps` · `set left_cps` · `set right_cps` · `CpsMinValue` · `CpsMaxValue` · `sldMinCPS` · `sldRMinCPS` · `get_CpsMax` · `get_cps` · `set_cps` · `slider_cps` · `Average Left CPS` · `Average Right CPS` · `Clicks per second` · `Maximum CPS are 20!` · `Minimum CPS is 1!` · `Randomizes Current CPS In Order To Make The Clicker Undetectable Server-Side`

**Jitter & click patterns**
`jitter` · `leftjitter` · `jitterclick` · `isJitterClick` · `Jitter Force` · `BLOCKHIT` · `Blockhit delay` · `Click Sound` · `Click Sounds` · `Click to break in debugger!` · `ClickerOnTop` · `Blatant Mode` · `No Hit Delay`

**Minecraft-specific hooks**
`Minecraft process found.` · `Waiting for minecraft process...` · `MC ONLY` · `key_key.hotbar.1` · `key_key.jump` · `key_key.sprint` · `key_key.inventory` · `Hotbar slots with pots` · `Anti AFK` · `Reach-> ` · `Min reach` · `Max reach` · `aim assist` · `throwpot##` · `toggle_block_break` · `toggle_inventory`

**Crystal / anchor / pearl macros**
`Crystal Slot` · `Hit Crystal` · `Slow Hit Crystal` · `CrystalKey` · `ToggleCrystal` · `Anchor Pearl` · `AirAnchor` · `Double Anchor` · `Pearl Catch` · `TogglePearlCatch:` · `Stun Slam` · `Breach Swap` · `ToggleBreachSwap` · `Shield Stun` · `Elytra Swap` · `Offhand Hotbar Totem` · `Inventory D-Hand` · `Fast XP`

**Injection & process manipulation**
`WriteProcessMemory` · `InjectionMethod` · `INJECTING...` · `NtWriteVirtualMemory` · `NtMapViewOfSection` · `NtUnmapViewOfSection` · `NtGetContextThread` · `tAllocateVirtualMemory` · `injector.cpp` · `Found javaw.exe` · `- injecting automatically...` · `Architecture mismatch between injector and target process.`

**Self-destruct & cleanup**
`self destruct` · `selfdel` · `Destructing...` · `btnDestruct_Click` · `Clear Temp` · `Clear Prefetch` · `prefetch_block` · `delete file on exit` · `RegDelValue` · `reg delete "HKCU\...\UserAssist" /f` · `reg delete "HKCU\...\RunMRU" /f` · `reg delete "HKLM\SYSTEM\MountedDevices" /f`


### Phase 7 — Entropy Analysis

For native (non-.NET) PE files, the tool calculates **Shannon entropy** on each PE section:

- Sections above **6.5 bits/byte** → high entropy
- Sections above **7.2 bits/byte** → very high entropy

Combined with known packer section names and a suspiciously low import count, this reliably identifies **packed or encrypted payloads** even when no string signatures are present at all.


### Phase 8 — VirusTotal Check

After analysis, the hash of each flagged file is computed and a VirusTotal lookup is offered. A browser tab opens directly on the VT results page — **no data is uploaded**, the check is hash-only and fully passive.


## Output

Results are color-coded in the console:

- 🟢 **CLEAN** — no suspicious indicators found
- 🔴 **FUCKED** — one or more detections triggered

For each flagged file the output includes: file name, type, size, Authenticode status, detected cheat client name (if `[CS]` matched), triggered YARA tags, and the specific strings that caused the hit.

When analyzing multiple files, a **summary** is printed at the end with clean/detected counts and the full list of flagged files with their respective tags.


## System Requirements

- Windows 10 / 11
- Run as **Administrator** (strongly recommended)
- .NET runtime (included in all modern Windows installs)


## Contacts

**Creator**: Tonynoh

💬 Discord: `tonyboy90_`

📎 GitHub: [MeowTonynoh](https://github.com/MeowTonynoh)

🎥 YouTube: tonynoh-07
