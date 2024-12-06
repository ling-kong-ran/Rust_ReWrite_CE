use std::thread::sleep;
use winapi::um::winnt;
use re_write_ce::base::process::Process;

fn main() {
    let process = Process::open(6932).unwrap();

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
    sleep(std::time::Duration::from_millis(1000));

    // 遍历所有页读取内存
    let mut target: i32 = 238792392;

    // 记录地址 用于下次扫描
    let mut locations = &mut Vec::with_capacity(regions.len());

    regions.into_iter().for_each(|region| {
        match process.read_memory(region.BaseAddress as _, region.RegionSize) {
            Ok(memory) => memory
                .windows(target.to_ne_bytes().len())
                .enumerate()
                .step_by(4)
                .for_each(|(offset, window)| {
                    if window == target.to_ne_bytes() {
                        locations.push(region.BaseAddress as usize + offset);
                    }
                }),
            Err(err) => eprintln!(
                "Failed to read {} bytes at {:?}: {}",
                region.RegionSize, region.BaseAddress, err,
            ),
        }
    });

    while locations.len() != 1 {
        locations.retain(|addr| match process.read_memory(*addr, target.to_ne_bytes().len()) {
            Ok(memory) => {
                if memory == target.to_ne_bytes() {
                    println!("match value at {}", addr);
                    return true;
                } else {
                    println!("memory read value: {:?}", memory);
                    return false;
                }
            },
            Err(_) => {
                println!("read memory at {}", addr);
                return false;
            }
        });
        println!("Now have {} locations", locations.len());



        let new_value: i32 = 100;
        locations
            .into_iter()
            .for_each(|addr| match process.write_memory(*addr, &new_value.to_ne_bytes()) {
                Ok(n) => eprintln!("Written {} bytes to [{:x}]", n, addr),
                Err(e) => eprintln!("Failed to write to [{:x}]: {}", addr, e),
            });
    }



}


