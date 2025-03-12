extern crate winapi;
extern crate libc;
#[macro_use]
extern crate log;
extern crate simplelog;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::processthreadsapi::{CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use winapi::ctypes::c_void;
use winapi::um::errhandlingapi::GetLastError;
use simplelog::{Config, LevelFilter, SimpleLogger};
use std::ffi::CString;

fn to_windows_str(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect()
}

fn inject_dll(process_handle: *mut c_void, dll_path: &str) -> bool {
    let dll_path_wide = to_windows_str(dll_path);
    let remote_memory = unsafe {
        VirtualAllocEx(
            process_handle,
            null_mut(),
            dll_path_wide.len() * 2,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_memory.is_null() {
        error!("Failed to allocate memory in target process.");
        return false;
    }

    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_memory,
            dll_path_wide.as_ptr() as *const _,
            dll_path_wide.len() * 2,
            null_mut(),
        );

        let load_library = GetProcAddress(LoadLibraryA(b"kernel32.dll\0".as_ptr() as *const i8), b"LoadLibraryW\0".as_ptr() as *const i8);

        if load_library.is_null() {
            error!("Failed to get address of LoadLibraryW.");
            return false;
        }

        let thread_handle = winapi::um::processthreadsapi::CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(load_library)),
            remote_memory,
            0,
            null_mut(),
        );

        if thread_handle.is_null() {
            error!("Failed to create remote thread.");
            return false;
        }

        WaitForSingleObject(thread_handle, winapi::um::winbase::INFINITE);
        CloseHandle(thread_handle);
    }

    true
}

fn main() {
    SimpleLogger::init(LevelFilter::Info, Config::default()).unwrap();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        error!("Usage: {} <target_executable> <dll_path>", args[0]);
        return;
    }

    let target_executable = &args[1];
    let dll_path = &args[2];

    // Konversi path ke C string
    let target_executable_cstr = CString::new(target_executable.as_str()).unwrap();

    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let success = unsafe {
        CreateProcessA(
            null_mut(),
            target_executable_cstr.as_ptr() as *mut i8, // Gunakan C string di sini
            null_mut(),
            null_mut(),
            0,
            0,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut process_info,
        )
    };

    if success == 0 {
        let error_code = unsafe { GetLastError() };
        error!("Failed to create process. Error code: {}", error_code);
        return;
    }

    info!("Created process with PID: {}", process_info.dwProcessId);

    if inject_dll(process_info.hProcess, dll_path) {
        info!("Injection successful.");
    } else {
        error!("Injection failed.");
    }

    unsafe {
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
    }
}