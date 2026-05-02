# ZK-ARCHE Comparative Benchmark Harness

This directory contains a self-contained harness that produces every figure and
the comparative summary table used in the **Experimental Result** chapter of
the thesis. It runs ZK-ARCHE, EDHOC, and mTLS through six tests and emits
PGFPlots `.tex` files that drop directly into the thesis's `Graphs/` folder
with no edits.

```
benchmarks/
├── setup.sh             # one-time prep: cargo build, cert generation
├── run_all.sh           # run every (test × protocol) on this host
├── plot.py              # consolidate CSVs/JSONs into .tex figures + PNGs
├── lib/                 # shared library (config, parsing, sampling, drivers)
├── tests/
│   ├── test1_concurrent.py     # 50 concurrent clients, single auth each
│   ├── test2_sequential.py     # 50 sequential auths from one client
│   ├── test3_highload.py       # 50 × 50 = 2500 auths under sustained load
│   └── test_resources.py       # tests 4/5/6 — peak RSS, CPU, energy estimate
└── results/             # written at runtime
    ├── raw/<test>_<proto>.csv
    └── summary/<test>_<proto>.json
```


## Quick start (per Raspberry Pi)

On each Pi (3B+, 4, 5) run:

```bash
git clone <this repo> && cd zk-arche-compare-main
bash benchmarks/setup.sh          # builds release binaries, generates certs
bash benchmarks/run_all.sh        # runs every test × protocol
```

That fills `benchmarks/results/{raw,summary}/` with CSV + JSON files. Then
copy that tree back to your laptop (e.g. `scp -r pi@host:.../benchmarks/results
./benchmarks/results-pi5/`) and from your laptop run:

```bash
python3 -m benchmarks.plot
```

This consolidates everything under `benchmarks/results/` into `benchmarks/graphs_tex/`
(PGFPlots) and `benchmarks/plots/` (PNG previews).

The PGFPlots filenames match the `\input{Graphs/...}` references in the
thesis chapter exactly:

| Output file | Used by |
| --- | --- |
| `test_1_graph.tex` | Fig. 1 (ZK-ARCHE — concurrent clients) |
| `test_2_graph.tex` | Fig. 2 (ZK-ARCHE — sequential auths) |
| `test_3_graph.tex` | Fig. 3 (ZK-ARCHE — high load) |
| `comparison_graph.tex` | Fig. 4 (latency comparison ZK-ARCHE / EDHOC / mTLS) |
| `test_4_graph.tex` | Fig. 5 (peak RSS) |
| `test_5_graph.tex` | Fig. 6 (peak CPU) |
| `test_6_graph.tex` | Fig. 7 (per-auth energy mJ) |
| `summary_table.tex` | Comparative summary table (`\input` it directly) |

Copy them into your thesis's `Graphs/` directory:

```bash
cp benchmarks/graphs_tex/*.tex /path/to/thesis/Graphs/
```


## Running individual tests

Every test takes a protocol argument (`zkarche`, `edhoc`, `mtls`, or `all`):

```bash
python3 -m benchmarks.tests.test1_concurrent zkarche
python3 -m benchmarks.tests.test2_sequential edhoc
python3 -m benchmarks.tests.test3_highload mtls
python3 -m benchmarks.tests.test_resources all
```

Results get written under `benchmarks/results/raw/` and
`benchmarks/results/summary/`.


## Tuning parameters

All sample sizes and other knobs come from environment variables read at
module-import time. The defaults match the thesis (50 concurrent clients,
50 sequential auths, 50×50 high load):

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZKB_T1_CLIENTS` | 50 | Test 1: concurrent clients |
| `ZKB_T2_RUNS` | 50 | Test 2: sequential auths from one client |
| `ZKB_T3_CLIENTS` | 50 | Test 3: number of parallel clients |
| `ZKB_T3_RUNS` | 50 | Test 3: auths per client |
| `ZKB_TR_CLIENTS` | 50 | Resource sampling: concurrent clients |
| `ZKB_TR_RUNS` | 5 | Resource sampling: auths per client |
| `ZKB_SAMPLE_S` | 0.05 | `/proc` sampler interval (seconds) |
| `ZKB_DEVICE` | auto | `pi3bplus` / `pi4` / `pi5` / `generic` |
| `ZKB_POWER_METER` | auto | `pmic` / `hwmon` / `static` (force a meter back-end) |
| `ZKB_PROTOS` | `zkarche,edhoc,mtls` | Limits which protocols `run_all.sh` runs |
| `ZKB_TESTS` | `test1,test2,test3,resources` | Limits which tests `run_all.sh` runs |

Quick sanity-check run (small numbers):

```bash
ZKB_T1_CLIENTS=8 ZKB_T2_RUNS=8 ZKB_T3_CLIENTS=4 ZKB_T3_RUNS=4 \
ZKB_TR_CLIENTS=4 ZKB_TR_RUNS=2 \
bash benchmarks/run_all.sh
```


## What each test measures

### Test 1 — Concurrent Clients (Single Authentication)

`TEST1_CONCURRENT_CLIENTS` (50) clients, each in its own working directory,
authenticate **at the same time** against the server. We record the per-client
latency. For ZK-ARCHE this means 50 distinct enrolled devices.

### Test 2 — Sequential Authentication (Single Client)

A single enrolled client performs `TEST2_SEQUENTIAL_RUNS` (50) authentications
back-to-back. The server is fresh for the run; the client reuses the same
device root. Tests whether per-session cost stays predictable across iterations.

### Test 3 — High-Load Scenario (Busy Traffic)

`TEST3_CLIENTS` (50) parallel sessions, each running `TEST3_RUNS_PER_CLIENT`
(50) sequential authentications, generating 2500 total. Captures behavior
under sustained concurrent demand.

### Tests 4 / 5 / 6 — Resource Consumption

A single combined run drives a representative load (default
`TEST_RESOURCES_CLIENTS=50` × `TEST_RESOURCES_RUNS_PER_CLIENT=5` = 250 auths)
while a `/proc/<pid>/{stat,status}` sampler watches the **server** process.
A separate power-meter sampler runs in parallel. From that one run we derive:

- **Test 4 — Memory**: peak resident set size in MiB.
- **Test 5 — CPU**: peak and mean CPU% (where 100% = one core busy).
- **Test 6 — Energy**: per-authentication energy in mJ.

For energy, the harness uses real hardware measurement when available
(`vcgencmd pmic_read_adc` on Pi 5; INA219/226/260 hwmon sensor on any Pi);
otherwise it falls back to a linear `P = idle + (max−idle)·u_cpu` model.
See the **Power measurement** section below for back-end selection,
calibration, and accuracy notes.


## Validation: how methodology matches the chapter

| Chapter requirement | Where in the harness |
| --- | --- |
| "Authentication latency $L_i = T^{end}_i - T^{start}_i$ ... timestamp when client initiates ... timestamp when authentication completes" | Each protocol's client binary records the duration around the authentication phase only (see `metrics::HandshakeMetrics` in the Rust code). The harness parses `CLIENT METRICS -> Duration: ...` from stdout. |
| "Mean latency $\bar L = \frac{1}{n}\sum L_i$" | `LatencyStats.from_values` in `lib/results.py`. |
| "$CPU_\text{norm} = T_\text{cpu} / (T_\text{wall} \cdot C) \times 100$" | `ProcSampler.summary().cpu_pct_normalised` in `lib/sampler.py` (sums utime+stime ticks per interval, divides by wall-clock and by core count). |
| "Memory consumption ... resident set size (RSS)" | Read from `/proc/<pid>/status:VmRSS` every `ZKB_SAMPLE_S`, peak retained. |
| "Communication overhead ... $B_\text{total}$" | Each Rust binary already counts bytes sent/received around the handshake. Captured via `Sent: X bytes, Received: Y bytes` line. |


## Power measurement

Per-authentication energy is measured (or estimated) at runtime by whichever
back-end is best for the host. The harness picks one automatically:

| Priority | Back-end | When it's used | Accuracy |
| --- | --- | --- | --- |
| 1 | `vcgencmd pmic_read_adc` | Pi 5 (DA9091 PMIC exposes per-rail V/I) | hardware-measured SoC power |
| 2 | INA219/226/260 via `/sys/class/hwmon` | any Pi with an INA sensor on the input rail | hardware-measured wall power |
| 3 | Static linear model `P = idle + (max−idle)·u_cpu` | fallback (Pi 3B+/4 with no sensor) | depends on profile accuracy |

The actual back-end used for a run lands in the JSON summary at
`resources.energy_method`, alongside per-rail samples. When a hardware meter
is present, the measured number replaces the model number, and the model
number is preserved under `resources.energy_per_auth_mJ_modelled` so you can
compare the two.

### Forcing a back-end

```bash
ZKB_POWER_METER=pmic    bash benchmarks/run_all.sh   # require Pi 5 PMIC
ZKB_POWER_METER=hwmon   bash benchmarks/run_all.sh   # require INA hwmon
ZKB_POWER_METER=static  bash benchmarks/run_all.sh   # force the linear model
```

### Calibrating the static-fallback profile

If you're on Pi 3B+ or Pi 4 without a hardware meter, the static-model numbers
are only as good as the `(idle_w, max_w)` you give them. The shipped defaults
come from published Pi power measurements (Eames raspi.tv 2018/2019,
pidramble, raspberry.tips 2026) but vary ±10–20% with PSU choice and what's
plugged into the USB ports.

Run the calibration helper while you watch a wall-plug power meter:

```bash
python3 -m benchmarks.tests.calibrate_power --duration 30
```

It drives the host to idle for 30 s, then saturates every CPU core for
another 30 s. If a `vcgencmd pmic_read_adc` or INA hwmon back-end is present
it prints the measured numbers automatically. Otherwise read your wall meter
during each phase and update the relevant `DevicePowerProfile` entry in
`benchmarks/lib/config.py`.

### Wiring an INA260 (recommended for thesis-grade Pi 3B+/4 numbers)

```bash
sudo modprobe ina2xx
echo ina260 0x40 | sudo tee /sys/class/i2c-adapter/i2c-1/new_device
ls /sys/class/hwmon/hwmon*/name           # confirm "ina260" appears
```

The harness's `HwmonInaMeter` will pick it up automatically the next time
you run `test_resources`.


## Combining results from multiple Pis

The chapter's figures 4/5/6 ("memory across platforms", "CPU across
platforms", "energy across platforms") show all three Pi platforms in one
chart with a bar per protocol per platform. The plotter produces this layout
when given multiple `--results` trees:

```bash
# On each Pi, after run_all.sh:
tar -C benchmarks -czf "results-$(hostname).tar.gz" results/

# On your laptop:
mkdir -p multi_host
for h in pi3 pi4 pi5; do
    mkdir -p "multi_host/$h"
    tar -C "multi_host/$h" -xzf "results-$h.tar.gz"
done

# Single command produces multi-host figures 4/5/6 + standard figs 1/2/3:
python3 -m benchmarks.plot \
    --results multi_host/pi3/results \
              multi_host/pi4/results \
              multi_host/pi5/results
```

The plotter detects each tree's device label from its summary JSONs (which
have a `"device": "Raspberry Pi 5 (8GB)"` field), orders them 3B+→4→5, and
emits grouped bars. Figures 1/2/3 and the latency-comparison chart use the
*first* tree (pick the one matching the chapter's main narrative platform);
the summary table does the same.


## Troubleshooting

- **`Missing release binaries`** — run `bash benchmarks/setup.sh` first.
- **ZK-ARCHE auth fails after the first few iterations** — the server bans IPs
  with more than 8 failures in 60 s. If auths are *succeeding*, you won't hit
  the limit; if they're failing, check `benchmarks/results/logs/` for the
  server stderr to see why.
- **`server on 127.0.0.1:4000 never accepted`** — usually means a previous
  run left a server bound to that port. Run `pkill -f zkarche_server`
  (or `edhoc_server` / `mtls_server`) and try again.
- **Energy numbers look wrong** — on Pi 5 the harness reads the on-board
  PMIC directly (`vcgencmd pmic_read_adc`) so the numbers should be
  hardware-accurate. On Pi 3B+/4 you're using the static linear model
  unless you wired up an INA sensor. Run
  `python3 -m benchmarks.tests.calibrate_power --duration 30` to verify
  the model's `(idle_w, max_w)` against your actual hardware, or wire an
  INA260 onto the input rail for direct measurement (see the
  **Power measurement** section).
