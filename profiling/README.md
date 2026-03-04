# Heap Profiling

Detect memory leaks in KMS core nodes using jemalloc heap profiling.

## How it works

The `heap-profiling` Cargo profile builds with jemalloc and preserves debug symbols. At runtime, jemalloc samples allocations and dumps heap snapshots on memory peaks and on `SIGUSR1`. Comparing two snapshots shows only allocations that *grew* — i.e., your leaks.

> **Note:** `heap-profiling` is used as both a Cargo **feature** (enables jemalloc code paths and SIGUSR1 handler) and a Cargo **profile** (preserves debug info for jeprof). The docker-compose file enables both automatically.

## Host dependencies

- **jeprof** (from gperftools) — reads jemalloc `.heap` dumps
- **graphviz** — renders SVG flamegraphs (`dot`)
- **addr2line** (from binutils) — resolves addresses to source lines

Install on Ubuntu/Debian:
```bash
sudo apt install google-perftools graphviz binutils
```

Install on macOS:
```bash
brew install gperftools graphviz binutils
```

## Usage

All commands run from the repo root.

### 1. Build

```bash
make build-compose-heap-profiling
```

### 2. Start

```bash
make start-compose-heap-profiling
```

Verify `[heap-profiling] Ready` appears in container logs.

### 3. Dump heap profiles

```bash
# Take a baseline dump before load
make dump-heap-profiles

# ... run your workload ...

# Take another dump after load
make dump-heap-profiles
```

This sends `SIGUSR1` to each core, copies `.heap` files, the binary, and `/proc/PID/maps` (for PIE address resolution) to `profiling/heap-dumps/`.

### 4. Analyze

```bash
./profiling/analyze-heap.sh ./profiling/heap-dumps/kms-server ./profiling/heap-dumps/core-1/
```

Output in `profiling/heap-analysis/`:

| File | Description |
|---|---|
| `top-leaks.txt` | Top allocation sites in the latest snapshot |
| `latest.svg` | Flamegraph of the latest snapshot |
| `diff-leaks.txt` | Allocation sites that grew between first and last snapshot |
| `diff.svg` | Diff flamegraph — **the most useful output** |

Open the `.svg` files in a browser. The diff shows only allocations that increased between the two dumps.

## Profiling

### `lg_prof_sample` trade-offs

The `lg_prof_sample` setting in `MALLOC_CONF` controls profiling granularity:

| Value | Sample interval | Overhead | Use case |
|---|---|---|---|
| `19` | 512 KB | ~1-2% | Quick smoke-test, production-safe |
| `12` | 4 KB | ~15-20% | Detailed leak hunting (default in this stack) |

Lower values capture more allocations but slow things down. The default is `12` for thorough profiling; bump to `19` if you only need a quick pass.

### Diagnosing leak type with Prometheus metrics

After deploying with the telemetry stack (included by default), compare these three metrics in Prometheus/Grafana:

| `kms_jemalloc_allocated` | `kms_jemalloc_resident` | `kms_process_memory_usage` (RSS) | Diagnosis |
|---|---|---|---|
| Staircases up | Staircases up | Staircases up | **Application-level leak** — objects allocated and never freed |
| Flat | Staircases up | Staircases up | **Allocator fragmentation** — freed memory can't be returned due to mixed page usage |
| Flat | Flat | Staircases up | **Non-jemalloc memory growth** — mmap, thread stacks, shared libs, etc. |

- `kms_jemalloc_allocated` — bytes the app actively holds via jemalloc
- `kms_jemalloc_resident` — bytes jemalloc has mapped from the OS (includes fragmentation)
- `kms_process_memory_usage` — total process RSS (includes non-jemalloc memory)

## Files

```
profiling/
├── README.md
├── analyze-heap.sh              # Analysis script (handles PIE/ASLR address resolution)
├── docker-compose-heap-profiling.yml  # Compose override (build args + MALLOC_CONF)
├── heap-dumps/                  # Dumped .heap files + binary + maps.txt (git-ignored)
└── heap-analysis/               # Analysis output (git-ignored)
```

## Troubleshooting

### Symbols show as `??:0`

jeprof needs three things to resolve addresses:

1. **Debug info in the binary** — the `heap-profiling` Cargo profile sets `debug=1` (line tables)
2. **`addr2line` on the host** — `which addr2line` (from binutils)
3. **`MAPPED_LIBRARIES:` section in the heap dump** — jemalloc writes this from `/proc/self/maps`. If missing, `make dump-heap-profiles` captures it separately as `maps.txt`, and `analyze-heap.sh` injects it automatically

If symbols still don't resolve, check:
```bash
# Binary has debug sections?
readelf -S ./profiling/heap-dumps/kms-server | grep debug

# Heap dump has MAPPED_LIBRARIES?
grep -c MAPPED_LIBRARIES ./profiling/heap-dumps/core-1/*.heap

# maps.txt was captured?
ls -l ./profiling/heap-dumps/core-1/maps.txt
```

### Negative diff totals

This happens when auto-dumps from `prof_gdump:true` (taken at memory peaks) get mixed with manual dumps. The script prefers manual dumps (from SIGUSR1) for diffing. For reliable diffs, always take two manual dumps: one before and one after your workload.
