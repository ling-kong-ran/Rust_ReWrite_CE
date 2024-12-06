use std::io;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::um::psapi::LIST_MODULES_ALL;
use winapi::um::winnt;

pub struct Process {
    pid: u32,
    handle : NonNull<c_void>
}

impl Process {
    pub fn open(pid:u32) -> io::Result<Self> {
        // 句柄
        let ptr = unsafe { winapi::um::processthreadsapi::OpenProcess(winnt::PROCESS_QUERY_INFORMATION | winnt::PROCESS_VM_READ, FALSE, pid) };
        NonNull::new(ptr)
            .map(|handle| Self { pid, handle })
            .ok_or_else(io::Error::last_os_error)

    }

    // 获取进程名
    pub fn name(&self) -> io::Result<String> {
        let mut module = MaybeUninit::<HMODULE>::uninit();
        let mut size = 0;
        // SAFETY: the pointer is valid and the size is correct.
        if unsafe {
            winapi::um::psapi::EnumProcessModulesEx(
                self.handle.as_ptr(),
                module.as_mut_ptr(), // out : 模块句柄列表
                size_of::<HMODULE>() as u32,
                &mut size, // 模块句柄列表的字节大小
                LIST_MODULES_ALL // 列出所有模块
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded, so module is initialized.
        let module = unsafe { module.assume_init() };
        // 进程名
        let mut buffer = Vec::<u8>::with_capacity(64);
        // SAFETY: the handle, module and buffer are all valid.
        let length = unsafe {
            winapi::um::psapi::GetModuleBaseNameA(
                self.handle.as_ptr(),
                module,
                buffer.as_mut_ptr().cast(),
                buffer.capacity() as u32,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded and length represents bytes.
        unsafe { buffer.set_len(length as usize) };
        Ok(String::from_utf8(buffer).unwrap())
    }

    // 读内存
    pub fn read_memory(&self, addr: usize, n: usize) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(n);
        let mut read = 0;

        // SAFETY: the buffer points to valid memory, and the buffer size is correctly set.
        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.handle.as_ptr(),
                addr as *const _,
                buffer.as_mut_ptr().cast(),
                buffer.capacity(),
                &mut read,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the call succeeded and `read` contains the amount of bytes written.
            unsafe { buffer.set_len(read as usize) };
            Ok(buffer)
        }
    }

    // 获取所有虚拟内存页信息
    pub fn memory_regions(&self) -> Vec<winnt::MEMORY_BASIC_INFORMATION> {
        let mut base = 0;
        let mut regions = Vec::new();
        let mut info = MaybeUninit::uninit();

        loop {
            // SAFETY: the info structure points to valid memory.
            let written = unsafe {
                winapi::um::memoryapi::VirtualQueryEx(
                    self.handle.as_ptr(),
                    base as *const _, // 基地址
                    info.as_mut_ptr(),
                    size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                break regions;
            }
            // SAFETY: a non-zero amount was written to the structure
            let info = unsafe { info.assume_init() };
            base = info.BaseAddress as usize + info.RegionSize; // 下一页的基地址
            regions.push(info);
        }
    }

    pub fn write_memory(&self, addr: usize, value: &[u8]) -> io::Result<usize> {
        let mut written = 0;

        // SAFETY: the input value buffer points to valid memory.
        if unsafe {
            winapi::um::memoryapi::WriteProcessMemory(
                self.handle.as_ptr(),
                addr as *mut _,
                value.as_ptr().cast(),
                value.len(),
                &mut written,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(written)
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // 关闭句柄
        unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
    }
}

// 枚举所有进程
pub fn enum_proc() -> io::Result<Vec<DWORD>> {
    // 所有的进程id
    let mut pids = Vec::<DWORD>::with_capacity(1024);
    let mut size = 0;
    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pids.as_mut_ptr(), // 进程标识符数组指针
            (pids.capacity() * size_of::<DWORD>()) as u32, // 数组的字节数大小
            &mut size, // 数组中实际有效的字节数大小
        )
    } == FALSE {
        // 返回系统错误
        return Err(io::Error::last_os_error());
    }
    // 用所有字节数 / 一个进程PID所占的字节数 就得出了 所有进程数
    let count = size as usize / size_of::<DWORD>();
    // SAFETY: the call succeeded and count equals the right amount of items.
    // 删除多余的数组内存
    unsafe { pids.set_len(count); }
    Ok(pids)
}
