Experimental project — use at your own risk.

BAAR is a lightweight archiver implemented in C. The primary interface is a command-line (CLI) tool with an optional GTK4-based GUI frontend. The CLI is feature-complete and is the authoritative interface for scripting and automation; the GUI offers an interactive view with drag & drop, browsing, and common archive operations.

IMPORTANT: The content below documents the CLI behavior (actual implemented commands and options) and describes the GUI features in detail. The CLI documentation reflects the implemented behavior in the source code.

## Command-line (CLI) usage

The CLI supports the following subcommands and options (exact behavior implemented in `src/baar.c`):

- Add files / create archive:
    - `baar a <archive> [files...] [-c 0|1|2|3|4] [-p password]`
        - Add files or directories to `<archive>` (the `.baar` extension is appended if missing).
        - Files may be specified as `src:dst` to control the path inside the archive.
        - Per-file compression level may also be provided using `src:level` style.

- Extract archive:
    - `baar x <archive> [dest_dir] [-p password]`
        - Extract all files from `<archive>` into `dest_dir` (current directory if omitted).

- List contents:
    - `baar l <archive> [-j|--json]`
        - List entries in human-readable form or JSON when `-j/--json` is used.

- Test integrity:
    - `baar t <archive> [-p password] [-j|--json]`
        - Decompress and CRC-check all entries to verify integrity.

- Repair / rebuild:
    - `baar f <archive>`
        - Rebuilds the archive, removing deleted or removed entries and compacting storage.

- Remove entry by id:
    - `baar r <archive> <id>`
        - Marks the entry with numeric id as deleted (logical removal).

- Search entries:
    - `baar search <archive> <pattern> [-j|--json]`
        - Search by name using shell wildcard patterns (`*`, `?`).

- Show entry metadata:
    - `baar info <archive> <id> [-j|--json]`
        - Display metadata for the entry with numeric id.

- Print entry contents to stdout:
    - `baar cat <archive> <id> [-p password]`

- Extract a single file by archive path:
    - `baar xx <archive> <entry_name> [-p password]`
        - Extracts the named entry (by path inside archive) to the current working directory.

- Create directory entry inside archive:
    - `baar mkdir <archive> path/to/dir`

- Rename an entry:
    - `baar rename <archive> <id> <new_name>`

- Recompress entries safely:
    - `baar compress <archive> -c 0|1|2|3|4 [-p password]`
        - Recompresses entries using the requested level (0=store, 1=fast, 2=balanced, 3=best, 4=ultra).

Notes on options and behavior:

- Compression levels: `-c 0`..`-c 4` (0 = store, 1 = fast, 2 = balanced, 3 = best, 4 = ultra).
- Password/encryption: `-p password` enables PBKDF2-derived stream XOR protection (PBKDF2 + HMAC-SHA256 keystream). The program validates passwords using CRC before writing extracted files. Legacy XOR compatibility mode can be enabled with the environment variable `BAAR_LEGACY_XOR=1`.
- JSON output: `-j` or `--json` yields machine-readable JSON for commands that support it (listing, testing, search, info).
- The archive format stores file data blobs first and an index at the end; the header contains an index offset. Deleting entries marks them as deleted; `f` (rebuild) rewrites a compacted archive.

Examples:

```
./baar a my.baar file1.txt file2.png -c 1
./baar l my.baar
./baar x my.baar ./out -p secret
./baar t my.baar -p secret
./baar r my.baar 3
./baar f my.baar
./baar --gui                    # Launch GUI (interactive)
./baar --gui my.baar            # Launch GUI and open archive
```

## GUI (GTK4) — detailed description

The GUI is an optional frontend implemented with GTK4. It provides an interactive archive browser and common operations. The GUI mirrors many CLI operations but is intended for manual interaction rather than automation. The GUI mode is enabled with `--gui`.

High-level GUI features and user interactions:

- Window and main layout:
    - When no archive is open, the GUI shows a simple welcome screen and toolbar with a `+` (open/create) button. When an archive is opened the main pane shows a list of entries (a `GtkListBox`) and an information panel on the right with selected-entry details (name, size, number of entries).

- Opening/creating archives:
    - Use the `+` control to open an existing archive file or to create a new `.baar` archive. If a user drops a `.baar` file onto the window when no archive is open, the GUI will open that archive.

- Browsing and navigation:
    - The archive view supports folder-style navigation. Virtual folders are provided for libarchive formats (ZIP/TAR) where explicit directory entries may be missing; double-clicking a folder drills down and a `..` parent row is shown to go up one level. The current folder prefix is tracked internally and the list is populated by filtering the loaded index.

- Adding files and directories:
    - With an archive open, click the add (`+`) button in the toolbar to add files or directories. Files may also be dropped onto the open archive window to add them.
    - The GUI supports recursive collection of files when adding directories.

- Removing entries and compacting:
    - Select entries and click the `-` button to mark them as deleted. Deleted entries remain in the archive until a rebuild/compact operation (`Compact` / `Refresh`) is invoked; `Compact` will rebuild the archive excluding deleted entries.

- Extracting files:
    - Select one or more entries and click the extract/save icon. The GUI will extract the selected entries to a destination chosen by the user. When dragging files out to the file manager (external drag), files are temporarily extracted to a per-process temporary directory such as `/tmp/baar_drag_<pid>/` and provided to the desktop as regular files for the drag operation.

- Drag & drop behavior (bidirectional):
    - Drag IN (into BAAR):
        - Dropping a `.baar` archive onto the application when no archive is open will open that archive.
        - Dropping files onto an already-open archive will add those files to the current archive (the user may be prompted for overwrite behavior if conflicts occur).
        - Dropping files when no archive is open will prompt the user to create a new archive and then add the files.

    - Drag OUT (from BAAR to file manager):
        - Dragging file rows from the archive view to an external file manager causes temporary extraction of the selected entries into a `/tmp/baar_drag_<pid>/` folder and supplies those files to the drag operation. Only file entries are supported for external drag; folders are not provided as a single droppable item.

- Internal drag & drop and moving entries:
    - The GUI implements internal drag & drop targets for moving items between folders inside BAAR (for the native `.baar` format). Internal moves are performed without extracting full file contents to the filesystem.

- Encryption and password handling in the GUI:
    - If an archive is encrypted or the user provides a `-p` password via the CLI when opening the GUI, the GUI stores a password in memory for operations that require decryption/encryption. When adding files to an encrypted archive the GUI will encrypt them with the current archive password. On certain drag operations the user may be asked whether to encrypt dropped data.

- Progress reporting and dialogs:
    - Long-running operations (add, extract, rebuild) display a progress dialog with a progress bar and descriptive text. Operations are run asynchronously so the UI remains responsive.

- Entry metadata and info panel:
    - Selecting a row shows metadata like uncompressed size, compressed size, CRC, compression level, and POSIX-like attributes (mode, uid, gid, mtime) in the info panel.

## Building and installation

Build with make (requires development packages listed below):

```
make
```

Install to system locations:

By default `make install` installs files under the chosen prefix (default: `/usr/local`).
You can override the prefix like this: `sudo make prefix=/usr install`.

Typical install destinations (where `${prefix}` defaults to `/usr/local`):

- Binary:
    - ${prefix}/bin/baar
- Desktop entry (desktop file):
    - ${prefix}/share/applications/baar.desktop
- AppStream / metainfo (if present):
    - ${prefix}/share/metainfo/baar.xml
- Man pages (if provided by the build):
    - ${prefix}/share/man/man1/baar.1
- Icons and other shared data (only if the project provides them):
    - ${prefix}/share/icons/hicolor/<size>/apps/
    - ${prefix}/share/icons/...

Install / uninstall commands:

```
# Install the built binary and resources to system locations (default: /usr/local)
sudo make install

# To use a different prefix (for example /usr):
sudo make prefix=/usr install

# To uninstall the files previously installed by `make install`:
sudo make uninstall
```

### Requirements (development packages)

- C compiler (gcc or clang)
- make
- zlib development libraries (e.g. `zlib1g-dev` on Debian/Ubuntu)
- libarchive development libraries (e.g. `libarchive-dev` on Debian/Ubuntu)
- GTK4 development libraries (for GUI, e.g. `libgtk-4-dev` on Debian/Ubuntu)

### Debian/Ubuntu example

```sh
sudo apt update
sudo apt install build-essential zlib1g-dev libarchive-dev libgtk-4-dev
```

## Running

Show help (CLI):

```sh
./baar --help
```

Run GUI:

```sh
./baar --gui
```

## Notes and implementation details

- Password protection: PBKDF2 (100k iterations) + HMAC-SHA256 is used to derive a pseudorandom keystream which is XORed with data blocks for simple stream encryption. CRC checks are used to detect incorrect passwords. For legacy compatibility a mode using an older XOR approach can be enabled with `BAAR_LEGACY_XOR=1`.
- Archive layout: data blobs are written first and a JSON-like index is written at the end; the header contains a pointer to the index offset. This enables the CLI to quickly read the index from the end of the file.
- Limitations: there is no authenticated encryption (no MAC/AES-GCM), some extended metadata may not be preserved, and rebuilding very large archives can be slow because the index is at the end.

For more low-level implementation notes, consult the source in `src/` (notably `src/baar.c` and `src/la_bridge.c`).
**Drag OUT (from BAAR):**
4. **Drag files to file manager**: Click and drag files from BAAR to Nautilus/desktop to extract them
   - Files are temporarily extracted to `/tmp/baar_drag_<pid>/`


# Installation and Running

## Requirements

To build and run you need:

- C compiler (gcc or clang)
- make
- zlib development libraries (e.g. `zlib1g-dev` on Debian/Ubuntu)
- libarchive development libraries (e.g. `libarchive-dev` on Debian/Ubuntu)
- GTK4 development libraries (for GUI, e.g. `libgtk-4-dev` on Debian/Ubuntu)

## Installing required packages

### Debian/Ubuntu:

```sh
sudo apt update
sudo apt install build-essential zlib1g-dev libarchive-dev libgtk-4-dev
```

### Fedora:

```sh
sudo dnf install gcc make zlib-devel libarchive-devel gtk4-devel
```

### Arch Linux:

```sh
sudo pacman -S base-devel zlib libarchive gtk4
```

### Solus:

```sh
sudo eopkg install -c system.devel
sudo eopkg install zlib-devel libarchive-devel gtk4-devel
```

## Building

```sh
make
```

## Installation

```sh
sudo make install
```

## Running

```sh
./baar --help
```
or for GUI:
```sh
./baar --gui
```
   - Metadata (permissions, modification time) is preserved
   - Only files can be dragged out (folders are not supported)
   - Encrypted archives are not supported for drag-out

For detailed drag & drop documentation, see [DRAG_AND_DROP.md](DRAG_AND_DROP.md).

Notes:

- Password protection uses PBKDF2 (100k iterations) + HMAC-SHA256 pseudostream (XOR with keystream blocks); CRC validates password correctness before writing files. For compatibility, set `BAAR_LEGACY_XOR=1` for legacy XOR mode.
- Format: data blobs first, index at end; header stores index offset.
- Deleting entries and rebuild rewrite the archive.

Build & Test Status (local):

- Build: PASS (compiled with gcc, small warning about unused helper)
- Basic tests: PASS (create, list, test, extract, remove, fix, password)

Limitations:

- Currently no authentication (HMAC generates keystream, not MAC); wrong password detected via CRC. For real security, add AES-GCM with tag.
- No comprehensive directory metadata support (some attributes not captured).
 - Basic POSIX mode/uid/gid/mtime and arbitrary key/value pairs are stored in the index.
- Index at end means slower rebuild for very large archives.

