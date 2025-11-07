use anyhow::Result;
use ghost_core::{memory, process};

fn main() -> Result<()> {
    env_logger::init();

    println!("Ghost - Process Injection Detection\n");

    let processes = process::enumerate_processes()?;
    println!("Found {} processes\n", processes.len());

    for proc in processes.iter().take(10) {
        println!("{}", proc);

        if let Ok(regions) = memory::enumerate_memory_regions(proc.pid) {
            let rwx_regions: Vec<_> = regions
                .iter()
                .filter(|r| r.protection == ghost_core::MemoryProtection::ReadWriteExecute)
                .collect();

            if !rwx_regions.is_empty() {
                println!("  RWX regions: {}", rwx_regions.len());
            }
        }
    }

    Ok(())
}
