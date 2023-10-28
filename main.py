import os
import ctypes
import sys
import psutil
import platform

def get_dll_path(dll_name):
    return os.path.join(os.path.dirname(__file__), dll_name)

def inject_dll(process_name, dll_name):
    # Find the target process by name
    target_process = None
    for process in psutil.process_iter(attrs=['pid', 'name']):
        if process.info['name'] == process_name:
            target_process = process
            break

    if target_process is None:
        print(f"Process not found: {process_name}")
        return

    process_id = target_process.info['pid']
    dll_path = get_dll_path(dll_name)

    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Open the target process
        process_handle = kernel32.OpenProcess(
            0x001F0FFF,  # PROCESS_ALL_ACCESS
            False,
            process_id
        )
        if not process_handle:
            raise ctypes.WinError(ctypes.get_last_error())

        # Allocate memory in the target process for the DLL path
        allocated_mem = kernel32.VirtualAllocEx(
            process_handle,
            None,
            len(dll_path),
            0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
            0x40  # PAGE_EXECUTE_READWRITE
        )
        if not allocated_mem:
            raise ctypes.WinError(ctypes.get_last_error())

        # Write the DLL path to the allocated memory
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(process_handle, allocated_mem, dll_path, len(dll_path), ctypes.byref(written)):
            raise ctypes.WinError(ctypes.get_last_error())

        # Load the DLL into the target process
        thread_id = ctypes.c_ulong(0)
        kernel32.CreateRemoteThread(
            process_handle,
            None,
            0,
            ctypes.WinFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(LoadLibraryA),
            allocated_mem,
            0,
            ctypes.byref(thread_id)
        )

        if not thread_id.value:
            raise ctypes.WinError(ctypes.get_last_error())

        print("DLL injected successfully.")
    except Exception as e:
        print(f"DLL injection failed: {str(e)}")

if __name__ == "__main__":
    process_name = input("Enter the name of the target process: ")
    dll_name = input("Enter the name of the DLL to inject: ")
    inject_dll(process_name, dll_name)
