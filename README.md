# Ghidra Monkey C Processor

A Ghidra extension for loading, analyzing, and disassembling Garmin Monkey C binaries (`.prg`).

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Ghidra](https://img.shields.io/badge/Ghidra-11.4.x-green.svg)

## Overview

This plugin adds support for the Monkey C bytecode format used by Garmin Connect IQ devices. It is designed to provide robust disassembly and static analysis capabilities, allowing reverse engineers to inspect classes, functions, and cross-references in `.prg` files.

**Note:** This plugin focuses on **Disassembly** and **Static Analysis**. It does not currently implement P-Code semantics for the Decompiler view.

You can read more about binary structure in the [research documentation](doc/prg.md)

## Features

*   **Automatic Loader:** Automatically detects valid Monkey C (`.prg`) files and loads them into memory.
*   **Class & Function Recovery:** Parses internal metadata to recreate Class structures and Function definitions in the Symbol Tree.
*   **Symbol Table Resolution:** 
    *   Populates the Ghidra Symbol Table with internal function names.
    *   Resolves Symbol IDs in the disassembly to their actual string names or values.
*   **String Resolution:** Automatically maps string resource IDs to their actual string values in the listing.
*   **Cross-References (XRefs):** Adds code and data cross-references to track usage of functions and fields.
*   **Auto-Analysis:** The Monkey C Analyzer runs automatically after loading to apply these markups.

## Installation

### From Release (Recommended)
1.  Download the latest release zip file from the [Releases](https://github.com/Gualdimar/MonkeyC-Ghidra-Plugin/releases) page.
2.  Open Ghidra.
3.  Go to **File** -> **Install Extensions**.
4.  Click the green **+** icon.
5.  Select the downloaded zip file.
6.  Restart Ghidra.

### From Source
Prerequisites: Gradle and a valid Ghidra installation.

1.  Clone this repository.
2.  Set the `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation path.
3.  Run the build command:
    ```bash
    gradle buildExtension
    ```
4.  The output zip will be located in the `dist/` folder.
5.  Install as described above.

## Usage

1.  **Import File:** Drag and drop a `.prg` file into the Ghidra Project window.
2.  **Select Format:** The loader will auto-detect "Monkey C". Click **OK**.
3.  **Analyze:** When prompted, ensure the **Monkey C Analyzer** is checked (it is selected by default). Click **Analyze**.
4.  **Inspect:** 
    *   Open the **Listing View** to see the disassembled bytecode with resolved names.
    *   Open the **Symbol Tree** to explore recovered Classes and Functions.
    *   Use **XRefs** (double-click or right-click) to navigate between function calls.

## Limitations

*   **Disassembly Only:** The Decompiler window will show empty or raw output because P-Code semantics are not implemented. Please rely on the Listing window for analysis.

## Contributing

Pull requests are welcome! If you find a `.prg` file that fails to load or have suggestions for better analysis, please open an issue.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is an independent tool and is not affiliated with, endorsed by, or associated with Garmin Ltd. "Monkey C" and "Connect IQ" are trademarks of Garmin.
