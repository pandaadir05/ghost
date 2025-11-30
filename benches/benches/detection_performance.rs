use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ghost_core::{DetectionEngine, MemoryProtection, MemoryRegion, ProcessInfo};

fn create_test_process() -> ProcessInfo {
    ProcessInfo {
        pid: 1234,
        ppid: 4,
        name: "test.exe".to_string(),
        path: Some("C:\\Windows\\System32\\test.exe".to_string()),
        thread_count: 4,
    }
}

fn create_memory_regions(count: usize) -> Vec<MemoryRegion> {
    (0..count)
        .map(|i| MemoryRegion {
            base_address: 0x10000000 + (i * 0x1000),
            size: 0x1000,
            protection: if i % 5 == 0 {
                MemoryProtection::ReadWriteExecute
            } else {
                MemoryProtection::ReadWrite
            },
            region_type: if i % 10 == 0 { "IMAGE" } else { "PRIVATE" }.to_string(),
        })
        .collect()
}

fn bench_detection_engine(c: &mut Criterion) {
    let mut engine = DetectionEngine::new().expect("Failed to create detection engine");
    let process = create_test_process();

    c.bench_function("process_analysis_small", |b| {
        let regions = create_memory_regions(10);
        b.iter(|| engine.analyze_process(black_box(&process), black_box(&regions), None))
    });

    c.bench_function("process_analysis_medium", |b| {
        let regions = create_memory_regions(100);
        b.iter(|| engine.analyze_process(black_box(&process), black_box(&regions), None))
    });

    c.bench_function("process_analysis_large", |b| {
        let regions = create_memory_regions(1000);
        b.iter(|| engine.analyze_process(black_box(&process), black_box(&regions), None))
    });
}

fn bench_shellcode_detection(c: &mut Criterion) {
    let detector = ghost_core::ShellcodeDetector::new();

    c.bench_function("shellcode_scan_1kb", |b| {
        let data = vec![0x90; 1024]; // 1KB of NOPs
        b.iter(|| detector.scan_memory_region(black_box(&data), black_box(0x10000000)))
    });

    c.bench_function("shellcode_scan_64kb", |b| {
        let data = vec![0x90; 65536]; // 64KB of NOPs
        b.iter(|| detector.scan_memory_region(black_box(&data), black_box(0x10000000)))
    });

    c.bench_function("shellcode_scan_with_patterns", |b| {
        let mut data = vec![0x90; 4096]; // 4KB base
                                         // Add some patterns that will trigger detection
        data[100] = 0x4D;
        data[101] = 0x5A; // MZ header
        data[200] = 0xFC;
        data[201] = 0x48; // Meterpreter pattern
        data[300] = 0x64;
        data[301] = 0x8B; // PEB access

        b.iter(|| detector.scan_memory_region(black_box(&data), black_box(0x10000000)))
    });
}

fn bench_memory_operations(c: &mut Criterion) {
    c.bench_function("memory_region_creation", |b| {
        b.iter(|| create_memory_regions(black_box(100)))
    });

    c.bench_function("memory_region_sorting", |b| {
        let mut regions = create_memory_regions(1000);
        b.iter(|| {
            regions.sort_by_key(|r| r.base_address);
            black_box(&regions);
        })
    });
}

criterion_group!(
    benches,
    bench_detection_engine,
    bench_shellcode_detection,
    bench_memory_operations
);
criterion_main!(benches);
