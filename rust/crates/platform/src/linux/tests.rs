//! Parser and sampler tests against captured text. The fixtures follow the
//! kernel's layout; host names, addresses and serials are made up.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::host::{chassis_type_label, cpu_metadata, khz_text_as_mhz, os_metadata};
use super::procfs::*;
use super::sampler::{Sampler, SysPaths};

mod sensors;

pub(crate) struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "lt-platform-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn write(&self, relative: &str, text: &str) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const PROC_STAT: &str = "\
cpu  2255 34 2290 22625563 6290 127 456 0 0 0
cpu0 1132 34 1441 11311718 3675 127 438 0 0 0
cpu1 1123 0 849 11313845 2614 0 18 0 0 0
intr 114930548 113199788 3 0 5 263 0 4 [...]
ctxt 1990473
btime 1062191376
processes 2915
procs_running 1
procs_blocked 0
";

const MEMINFO: &str = "\
MemTotal:       16375088 kB
MemFree:         9010104 kB
MemAvailable:   14678772 kB
Buffers:          189468 kB
Cached:          5302352 kB
SwapTotal:       1048572 kB
SwapFree:        1048572 kB
";

fn net_dev(eth0: (u64, u64), docker0: Option<(u64, u64)>) -> String {
    let mut text = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
         lo: 9926341   50413    0    0    0     0          0         0  9926341   50413    0    0    0     0       0          0\n",
    );
    text.push_str(&format!(
        "  eth0: {} 1200 0 0 0 0 0 4 {} 900 0 0 0 0 0 0\n",
        eth0.0, eth0.1
    ));
    if let Some((rx, tx)) = docker0 {
        text.push_str(&format!(
            "docker0: {rx} 10 0 0 0 0 0 0 {tx} 10 0 0 0 0 0 0\n"
        ));
    }
    text
}

// Fault: a bad CPU line is read as numbers (or a short line indexes past
// its end), so the Hub shows a made-up CPU value.
#[test]
fn cpu_line_needs_four_numbers_and_every_column_parsed() {
    let times = parse_cpu_times(PROC_STAT).unwrap();
    assert_eq!(times.total, 2255 + 34 + 2290 + 22625563 + 6290 + 127 + 456);
    assert_eq!(times.idle, 22625563 + 6290, "idle plus iowait");
    assert_eq!(
        parse_cpu_times("cpu  1 2 3\n"),
        Err(CpuStatError::TooFewFields)
    );
    assert!(matches!(
        parse_cpu_times("cpu  1 2 x 4 5\n"),
        Err(CpuStatError::NotANumber(_))
    ));
    assert_eq!(
        parse_cpu_times("cpu0 1 2 3 4 5\n"),
        Err(CpuStatError::NoCpuLine)
    );
}

// Fault: counters that go backwards (a VM restored from a snapshot, a
// counter reset) panic on subtraction in a debug build or give a value
// outside 0..100. Go wraps the subtraction and the result is clamped.
#[test]
fn cpu_counters_that_go_backwards_do_not_panic() {
    let previous = CpuTimes {
        idle: 800,
        total: 1000,
    };
    let current = CpuTimes {
        idle: 400,
        total: 500,
    };
    let value = super::sampler::clamp_percent(cpu_percent(previous, current));
    assert!((0.0..=100.0).contains(&value), "{value}");
    let busy = cpu_percent(
        CpuTimes {
            idle: 400,
            total: 500,
        },
        CpuTimes {
            idle: 440,
            total: 600,
        },
    );
    assert!((busy - 60.0).abs() < 1e-9, "{busy}");
    assert_eq!(cpu_percent(current, current), 0.0, "no time passed");
}

// Fault: guest and guest_nice time, which the kernel already counts in user
// and nice, is added to the total a second time, so a host that runs VMs
// (a Proxmox node, for example) reports CPU use higher than it is.
#[test]
fn cpu_total_counts_guest_time_once() {
    // Ten seconds on a 4-core host (4000 ticks at 100 Hz). Deltas:
    // user +1800 (guest +1600 of it), nice +100 (guest_nice +100 of it),
    // system +200, idle +1800, iowait +20, softirq +80.
    // Total of the first eight columns: 1800+100+200+1800+20+0+80+0 = 4000.
    // Idle (idle+iowait): 1820. Busy: (4000-1820)/4000 = 54.5 %.
    // Adding guest and guest_nice again gives (5700-1820)/5700 = 68.07 %.
    let previous = parse_cpu_times("cpu  4705 120 1503 89012 312 0 85 0 2400 30\n").unwrap();
    let current = parse_cpu_times("cpu  6505 220 1703 90812 332 0 165 0 4000 130\n").unwrap();
    let busy = cpu_percent(previous, current);
    assert!((busy - 54.5).abs() < 1e-9, "{busy}");
    // A kernel with only seven columns still adds all of them.
    assert_eq!(
        parse_cpu_times("cpu  10 0 5 80 5 0 0\n"),
        Ok(CpuTimes {
            idle: 85,
            total: 100
        })
    );
}

// Fault: memory is read from the wrong field, or a kernel without a
// MemAvailable line (before 3.14) reads as zero available, so the host shows
// 100 % memory used.
#[test]
fn memory_follows_the_go_rules_for_missing_fields() {
    let percent = memory_used_percent(MEMINFO);
    assert!((percent - 10.359_126_008_971_677).abs() < 1e-9, "{percent}");
    // Available = MemFree + Buffers + Cached = 512344+301220+4211532 = 5025096
    // kB. Used = (8058888-5025096)/8058888 = 37.645 %.
    let old_kernel = "\
MemTotal:        8058888 kB
MemFree:          512344 kB
Buffers:          301220 kB
Cached:          4211532 kB
SwapCached:         1024 kB
Active:          4102332 kB
Inactive:        2733000 kB
SwapTotal:       2097148 kB
SwapFree:        2090000 kB
";
    let percent = memory_used_percent(old_kernel);
    assert!((percent - 37.645_292_998_239_95).abs() < 1e-9, "{percent}");
    // A MemAvailable line that says 0 is used as it is.
    let zero = "MemTotal: 8058888 kB\nMemFree: 512344 kB\nMemAvailable: 0 kB\nCached: 4211532 kB\n";
    assert_eq!(memory_used_percent(zero), 100.0);
    assert_eq!(memory_used_percent("MemTotal: 1000 kB\n"), 100.0);
    assert_eq!(memory_used_percent("MemAvailable: 10 kB\n"), 0.0);
    assert_eq!(
        memory_used_percent("MemTotal: 10 kB\nMemAvailable: 20 kB\n"),
        0.0
    );
    assert_eq!(mem_total_bytes(MEMINFO), 16_375_088 * 1024);
    assert_eq!(mem_total_bytes("MemFree: 1 kB\n"), 0);
}

// Fault: loopback traffic or a short row is counted, so the network chart
// shows the agent's own local traffic or garbage.
#[test]
fn network_totals_skip_loopback_and_short_rows() {
    let text = net_dev((1000, 2000), Some((50, 60))) + "  bad0: 1 2 3\n";
    assert_eq!(net_totals(&text), (1050, 2060));
    assert_eq!(interface_count(&text), 3, "eth0, docker0 and the short row");
    assert_eq!(net_totals(""), (0, 0));
}

// Fault: a rate is computed from a counter that went down (an interface
// went away, a driver reset), giving a negative or huge value.
#[test]
fn rate_is_zero_when_a_counter_goes_down_or_no_time_passed() {
    assert_eq!(rate_per_sec(1600.0, 1000.0, 10.0), 0.0);
    assert_eq!(rate_per_sec(1000.0, 1600.0, 0.0), 0.0);
    assert_eq!(rate_per_sec(1000.0, 1600.0, 10.0), 60.0);
}

const CPUINFO: &str = "\
processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz
physical id\t: 0
siblings\t: 2
cpu cores\t: 1

processor\t: 1
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz
physical id\t: 1
siblings\t: 2
cpu cores\t: 1
";

// Fault: the hardware card shows the wrong core or socket count, or a
// broken frequency file (NaN, Inf) is shown as a number.
#[test]
fn cpu_details_count_sockets_and_reject_bad_frequencies() {
    let meta = cpu_metadata(Some(CPUINFO), 99, Some("3400000"), Some("NaN"));
    assert_eq!(
        meta["cpu_model"],
        "Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz"
    );
    assert_eq!(meta["cpu_vendor"], "GenuineIntel");
    assert_eq!(meta["cpu_threads_logical"], "2");
    assert_eq!(meta["cpu_sockets"], "2");
    assert_eq!(meta["cpu_cores_per_socket"], "1");
    assert_eq!(meta["cpu_cores_physical"], "2");
    assert_eq!(meta["cpu_threads_per_socket"], "2");
    assert_eq!(meta["cpu_max_mhz"], "3400");
    assert!(!meta.contains_key("cpu_min_mhz"));
    for raw in ["Inf", "-Inf", "0", "-5", "None"] {
        assert_eq!(khz_text_as_mhz(raw), None, "{raw}");
    }
    // No processor lines: Go falls back to its CPU count, one socket.
    let meta = cpu_metadata(Some("vendor_id : AuthenticAMD\n"), 4, None, None);
    assert_eq!(meta["cpu_threads_logical"], "4");
    assert_eq!(meta["cpu_sockets"], "1");
    assert!(cpu_metadata(None, 4, Some("1000"), None).is_empty());
}

// Fault: the OS or chassis shown in the Hub differs from the Go agent's.
#[test]
fn os_release_and_chassis_match_go() {
    let release =
        "NAME=\"Debian GNU/Linux\"\nVERSION_ID='13'\n# comment\nID=debian\nPRETTY_NAME=\n";
    let meta = os_metadata(Some(release), Some("6.12.0-test".into()), None);
    assert_eq!(meta["os_name"], "Debian GNU/Linux");
    assert_eq!(meta["os_version_id"], "13");
    assert_eq!(meta["os_id"], "debian");
    assert!(
        !meta.contains_key("os_pretty_name"),
        "empty values are left out"
    );
    assert_eq!(meta["kernel_release"], "6.12.0-test");
    assert_eq!(chassis_type_label("1"), "other");
    assert_eq!(chassis_type_label("23"), "rack mount chassis");
    assert_eq!(chassis_type_label("36"), "stick pc");
    assert_eq!(chassis_type_label("99"), "99");
    assert_eq!(chassis_type_label("Rack"), "Rack");
}

fn sampler_paths(dir: &TempDir) -> SysPaths {
    SysPaths {
        proc_stat: dir.0.join("stat"),
        proc_meminfo: dir.0.join("meminfo"),
        proc_net_dev: dir.0.join("net_dev"),
        root: dir.0.join("root"),
        sys: dir.0.join("sys"),
    }
}

// Faults: the first sample reports a CPU or network value without a
// previous one; disk is not cached for a minute; an interface that goes
// away gives a negative rate. Same fixtures and results as Go's
// TestCollectReadsTelemetryFixturesAndCachesSlowSensors.
#[test]
fn sampler_first_sample_rates_and_disk_cache() {
    let dir = TempDir::new("sampler");
    dir.write("stat", "cpu  100 0 0 400 0 0 0 0 0 0\n");
    dir.write(
        "meminfo",
        "MemTotal:       100000 kB\nMemAvailable:    25000 kB\n",
    );
    dir.write("net_dev", &net_dev((1000, 2000), Some((0, 0))));
    // A link to the checkout, whose filesystem holds data; removing the
    // link later makes statfs fail.
    std::os::unix::fs::symlink(env!("CARGO_MANIFEST_DIR"), dir.0.join("root")).unwrap();
    let mut sampler = Sampler::new(sampler_paths(&dir));
    let start = Instant::now();

    let (first, _) = sampler.collect(start);
    assert_eq!(first.cpu_percent, 0.0);
    assert_eq!(
        (first.net_rx_bytes_per_sec, first.net_tx_bytes_per_sec),
        (0.0, 0.0)
    );
    assert!((first.memory_percent - 75.0).abs() < 1e-9);
    assert!(
        first.disk_percent > 0.0,
        "statfs of the checkout's filesystem"
    );

    dir.write("stat", "cpu  140 0 0 440 20 0 0 0 0 0\n");
    dir.write("net_dev", &net_dev((1600, 2600), Some((0, 0))));
    fs::remove_file(dir.0.join("root")).unwrap();
    let (second, _) = sampler.collect(start + Duration::from_secs(10));
    assert!((second.cpu_percent - 40.0).abs() < 1e-9);
    assert!((second.net_rx_bytes_per_sec - 60.0).abs() < 1e-9);
    assert!((second.net_tx_bytes_per_sec - 60.0).abs() < 1e-9);
    assert_eq!(
        second.disk_percent, first.disk_percent,
        "disk is reused within a minute"
    );

    let (third, _) = sampler.collect(start + Duration::from_secs(70));
    assert_eq!(
        third.disk_percent, 0.0,
        "read again after a minute: gone, so 0"
    );
    dir.write("net_dev", &net_dev((10, 20), None));
    let (fourth, _) = sampler.collect(start + Duration::from_secs(80));
    assert_eq!(
        (fourth.net_rx_bytes_per_sec, fourth.net_tx_bytes_per_sec),
        (0.0, 0.0)
    );
}

// Fault: an unreadable /proc/stat leaves the old counters in place, so the
// next sample computes CPU over the gap instead of starting again at 0.
#[test]
fn sampler_restarts_cpu_after_a_failed_read() {
    let dir = TempDir::new("cpu-fail");
    dir.write("stat", "cpu  100 0 0 400 0 0 0 0 0 0\n");
    let mut sampler = Sampler::new(sampler_paths(&dir));
    let start = Instant::now();
    sampler.collect(start);
    dir.write("stat", "garbage\n");
    assert_eq!(
        sampler
            .collect(start + Duration::from_secs(10))
            .0
            .cpu_percent,
        0.0
    );
    dir.write("stat", "cpu  140 0 0 440 20 0 0 0 0 0\n");
    assert_eq!(
        sampler
            .collect(start + Duration::from_secs(20))
            .0
            .cpu_percent,
        0.0
    );
}
