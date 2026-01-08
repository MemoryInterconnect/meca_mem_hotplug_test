# MECA Memory Hotplug Test

An interactive terminal utility for testing Linux memory hotplug functionality, specifically designed for MECA (Memory-Extended Computing Architecture) systems.

## Features

- Real-time memory usage visualization with colored ASCII bars
- Memory hotplug support - dynamically add/remove memory blocks
- Memory allocation testing - allocate and free memory blocks
- Parses `/proc/zoneinfo` for zone statistics
- Supports DMA32 (Local) and Movable (MECA) memory zones
- Cross-compilation support for RISC-V and x86-64

## Build

```bash
# Build for RISC-V 64-bit (default)
make

# Build for x86-64
CROSS_COMPILE= make

# Build with custom cross-compiler
CROSS_COMPILE=arm-linux-gnueabihf- make

# Clean build artifacts
make clean
```

The project uses static linking for standalone binaries.

## Usage

```bash
# Run with default /proc/zoneinfo
sudo ./meca_mem_hotplug_test

# Run with custom zoneinfo file (for testing)
./meca_mem_hotplug_test /path/to/zoneinfo

# Show help
./meca_mem_hotplug_test --help
```

**Note:** Root privileges are required for memory hotplug operations.

## Interactive Commands

| Key | Action |
|-----|--------|
| `a` | Add (hotplug) 128MB MECA memory block |
| `r` | Remove (offline) MECA memory block |
| `s` | Allocate 100MB user memory |
| `d` | Deallocate user memory |
| `q` | Quit |

## Display

The utility displays three memory bars:

1. **Total Memory** - Combined DMA32 + Movable zones
2. **Local Memory** - DMA32 zone (system memory)
3. **MECA Memory** - Movable zone (hotplugged memory)
3. **User Allocated Memory** - Allocated Memory

Each bar shows:
- Red: Used memory
- Yellow: Cached memory
- Green/Cyan: Free memory

## Memory Configuration

| Parameter | Value |
|-----------|-------|
| MECA Base Address | 0x200000000 (8GB) |
| MECA Max Size | 8GB |
| Memory Block Size | 128MB (system dependent) |
| Allocation Size | 100MB per block |

## Requirements

- Linux kernel with memory hotplug support (`CONFIG_MEMORY_HOTPLUG`)
- `/sys/devices/system/memory/probe` for memory probing
- Root privileges for hotplug operations

## Test Data

The repository includes `proc_zoneinfo.txt` with sample zoneinfo data for testing without a live system.

## License

See source file for license information.
