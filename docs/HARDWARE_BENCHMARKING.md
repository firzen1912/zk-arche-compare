# Hardware Resource Benchmarking

Use `experiments/hardware/hardware_resource_benchmark.py` on actual Raspberry Pi
or Ubuntu hardware to measure process-level CPU time, normalized CPU percentage,
peak RSS memory, and optional power/energy.

## Install

```bash
python3 -m pip install -r requirements.txt
```

## Client-side example

```bash
python3 experiments/hardware/hardware_resource_benchmark.py \
  --protocol zkarche \
  --role client \
  --device "Raspberry Pi 4" \
  --server "Core i7-6770HQ 2.60GHz" \
  --runs 50 \
  --cmd './target/release/zkarche_client --server 192.168.1.10:4000' \
  --power-mode fixed \
  --fixed-power-watts 3.2
```

## Hardware power sensor example

If an INA219/INA226/INA260 or similar sensor exposes power through hwmon:

```bash
python3 experiments/hardware/hardware_resource_benchmark.py \
  --protocol edhoc \
  --role client \
  --device "Raspberry Pi 5" \
  --runs 50 \
  --cmd './target/release/edhoc_client 192.168.1.10:5688' \
  --power-mode hwmon \
  --power-path /sys/class/hwmon/hwmon2/power1_input \
  --power-unit microwatt
```

Use `--power-mode fixed` only for estimated energy. Use `--power-mode hwmon`
when reporting measured energy from a real sensor.
