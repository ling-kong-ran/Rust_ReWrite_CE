use winapi::um::winnt;
use re_write_ce::base::process::Process;

fn main() {
    let process = Process::open(14404).unwrap();

    let mask = winnt::PAGE_EXECUTE_READWRITE
        | winnt::PAGE_EXECUTE_WRITECOPY
        | winnt::PAGE_READWRITE
        | winnt::PAGE_WRITECOPY;

    // 收集所有的页
    let regions = process
        .memory_regions()
        .into_iter()
        .filter(|p| (p.Protect & mask) != 0)
        .collect::<Vec<_>>();

    println!("Scanning {} memory regions", regions.len());

    // 遍历所有页读取内存
    let mut target: i32 = 32;

    // 记录地址 用于下次扫描
    let mut locations = Vec::with_capacity(regions.len());
    while locations.len() != 1 {
        locations.retain(|addr| match process.read_memory(*addr, target.to_ne_bytes().len()) {
            Ok(memory) => memory == target.to_ne_bytes(),
            Err(_) => false,
        });
    }

    let new_value: i32 = 100;
    locations
        .into_iter()
        .for_each(|addr| match process.write_memory(addr, &new_value.to_ne_bytes()) {
            Ok(n) => eprintln!("Written {} bytes to [{:x}]", n, addr),
            Err(e) => eprintln!("Failed to write to [{:x}]: {}", addr, e),
        });
}


