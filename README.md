# susDLL

susDLL is a tool designed for creating module definition files from DLLs, updating C files with formatted shellcode, and compiling malicious DLLs. This tool leverages `pefile` for parsing PE files and `x86_64-w64-mingw32-gcc` for compiling DLLs. 

## Features

- **Module Definition File Creation**: Extracts export symbols from a given DLL and creates a corresponding `.def` file.
- **Shellcode Formatting**: Formats shellcode bytes into a C string for easy inclusion in C source files.
- **C File Update**: Replaces placeholders in a C source file with formatted shellcode.
- **DLL Compilation**: Compiles the updated C file into a DLL using `mingw32-gcc`.

## Requirements

- Python 3.x
- `pefile` library
- `x86_64-w64-mingw32-gcc`

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/susDLL.git
    cd susDLL
    ```

2. Install the required Python library:
    ```sh
    pip install pefile
    ```

3. Ensure `x86_64-w64-mingw32-gcc` is installed on your system.

## Usage

```sh
python susDLL.py <dll_path> [-s <shellcode_path>]
