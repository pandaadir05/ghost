//! Tests for memory operations and protection detection

#[cfg(test)]
mod tests {
    use ghost_core::{MemoryProtection, MemoryRegion};

    #[test]
    fn test_memory_protection_levels() {
        assert_eq!(format!("{}", MemoryProtection::NoAccess), "---");
        assert_eq!(format!("{}", MemoryProtection::ReadOnly), "R--");
        assert_eq!(format!("{}", MemoryProtection::ReadWrite), "RW-");
        assert_eq!(format!("{}", MemoryProtection::Execute), "--X");
        assert_eq!(format!("{}", MemoryProtection::ReadExecute), "R-X");
        assert_eq!(format!("{}", MemoryProtection::ReadWriteExecute), "RWX");
        assert_eq!(format!("{}", MemoryProtection::WriteCopy), "WC-");
    }

    #[test]
    fn test_memory_region_creation() {
        let region = MemoryRegion {
            base_address: 0x400000,
            size: 0x1000,
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        };

        assert_eq!(region.base_address, 0x400000);
        assert_eq!(region.size, 0x1000);
        assert_eq!(region.protection, MemoryProtection::ReadExecute);
    }

    #[test]
    fn test_suspicious_memory_patterns() {
        // RWX region is highly suspicious
        let rwx_region = MemoryRegion {
            base_address: 0x10000000,
            size: 0x5000,
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        };

        assert_eq!(rwx_region.protection, MemoryProtection::ReadWriteExecute);
        assert_eq!(rwx_region.region_type, "PRIVATE");
    }

    #[test]
    fn test_normal_memory_patterns() {
        // Read-only IMAGE region is normal
        let normal_region = MemoryRegion {
            base_address: 0x400000,
            size: 0x10000,
            protection: MemoryProtection::ReadOnly,
            region_type: "IMAGE".to_string(),
        };

        assert_eq!(normal_region.protection, MemoryProtection::ReadOnly);
        assert_eq!(normal_region.region_type, "IMAGE");
    }

    #[test]
    fn test_memory_region_display() {
        let region = MemoryRegion {
            base_address: 0x10000000,
            size: 0x1000,
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        };

        let display = format!("{}", region);
        assert!(display.contains("RWX"));
        assert!(display.contains("PRIVATE"));
        assert!(display.contains("0x10000000"));
    }

    #[test]
    fn test_region_types() {
        let types = vec!["IMAGE", "MAPPED", "PRIVATE"];

        for region_type in types {
            let region = MemoryRegion {
                base_address: 0x10000000,
                size: 0x1000,
                protection: MemoryProtection::ReadOnly,
                region_type: region_type.to_string(),
            };
            assert_eq!(region.region_type, region_type);
        }
    }

    #[test]
    fn test_memory_protection_equality() {
        assert_eq!(MemoryProtection::ReadOnly, MemoryProtection::ReadOnly);
        assert_ne!(MemoryProtection::ReadOnly, MemoryProtection::ReadWrite);
        assert_ne!(MemoryProtection::ReadExecute, MemoryProtection::ReadWriteExecute);
    }

    #[test]
    fn test_large_memory_region() {
        let large_region = MemoryRegion {
            base_address: 0x10000000,
            size: 100 * 1024 * 1024, // 100MB
            protection: MemoryProtection::ReadWrite,
            region_type: "MAPPED".to_string(),
        };

        assert_eq!(large_region.size, 104_857_600);
    }

    #[test]
    fn test_small_memory_region() {
        let small_region = MemoryRegion {
            base_address: 0x10000000,
            size: 0x100, // 256 bytes
            protection: MemoryProtection::ReadExecute,
            region_type: "PRIVATE".to_string(),
        };

        assert_eq!(small_region.size, 256);
    }
}
