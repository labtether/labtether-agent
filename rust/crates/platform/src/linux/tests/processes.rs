//! The process list against captured `/proc` text and a made-up tree, and
//! the `ps` text rules against lines procps-ng 4.0.4 printed on a Debian 13
//! VM. Each test names the fault it catches. Users and commands are made up.

use super::TempDir;
use crate::linux::processes::{
    ProcPaths, ProcessRow, go_row, parse_passwd, parse_stat, parse_status, process_list_with,
};
use crate::linux::procps::{
    TextMode, command_text, cpu_percent, cpu_tenths, memory_percent, user_text,
};

// Fault: the name is cut at the first `)` (a name may hold one), or the
// state, CPU ticks or start time are read from the wrong field.
#[test]
fn stat_counts_fields_from_the_last_parenthesis() {
    let text = b"4242 (my (odd) job) S 1 4242 4242 0 -1 4194560 120 0 0 0 250 50 0 0 20 0 1 0 51234 1000 200 18446744073709551615";
    let stat = parse_stat(text).unwrap();
    assert_eq!(stat.comm, b"my (odd) job");
    assert_eq!(stat.state, b'S');
    assert_eq!(stat.busy_ticks, 300);
    assert_eq!(stat.start_ticks, 51234);
}

// Fault: the real user ID is used in place of the effective one, a kernel
// thread without `VmRSS` is dropped, or a later passwd line wins.
#[test]
fn status_and_passwd_follow_ps() {
    let status =
        "Name:\tsleep\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\nVmRSS:\t   896 kB\n";
    assert_eq!(parse_status(status), Some((0, 896)));
    assert_eq!(
        parse_status("Name:\tkthreadd\nUid:\t0\t0\t0\t0\n"),
        Some((0, 0))
    );
    assert_eq!(parse_status("Name:\tgone\n"), None);
    let users = parse_passwd(
        "root:x:0:0:root:/root:/bin/bash\nbackup2:x:0:0::/:/bin/sh\nbad line\ndemo:x:1000:1000::/home/demo:/bin/sh\n",
    );
    assert_eq!(users.get(&0).map(String::as_str), Some("root"));
    assert_eq!(users.get(&1000).map(String::as_str), Some("demo"));
}

// The `ps` lines these cases copy, from the lab VM (C locale):
//   root      608655  0.0  0.0     0 [Xvfb] <defunct>
//   systemd+     612  0.0  0.0  7036 /usr/lib/systemd/systemd-timesyncd
// Fault: NULs or newlines in a command line are not turned into spaces, a
// kernel thread is not shown as `[name]`, a zombie lacks ` <defunct>`, a
// control or non-ASCII byte is not escaped the way the locale says, or a
// command line of only NULs is not `?`.
#[test]
fn command_text_matches_ps() {
    let plain = TextMode::Plain;
    assert_eq!(
        command_text(
            b"/usr/bin/demo\0--flag\0two\nlines\0\0",
            b"demo",
            b'S',
            plain
        ),
        "/usr/bin/demo --flag two lines"
    );
    assert_eq!(command_text(b"", b"kthreadd", b'S', plain), "[kthreadd]");
    assert_eq!(command_text(b"", b"Xvfb", b'Z', plain), "[Xvfb] <defunct>");
    assert_eq!(
        command_text(b"a\tb\x7f c\xc3\xa9", b"a", b'S', plain),
        "a.b. c??"
    );
    assert_eq!(command_text(b"\0\0", b"x", b'S', plain), "?");
    let utf8 = TextMode::Utf8;
    assert_eq!(
        command_text("café\tbar".as_bytes(), b"c", b'S', utf8),
        "café?bar"
    );
    assert_eq!(command_text(b"x\xc2\x85y\xffz", b"x", b'S', utf8), "x??y?z");
}

// Fault: a long user name is printed whole (`ps` cuts it to seven bytes and
// `+` in its 8-wide column), or a user with no passwd entry is not shown by
// number.
#[test]
fn user_column_matches_ps() {
    let plain = TextMode::Plain;
    assert_eq!(user_text(Some("systemd-timesync"), 997, plain), "systemd+");
    assert_eq!(user_text(Some("backup01"), 34, plain), "backup01");
    assert_eq!(user_text(Some("root"), 0, plain), "root");
    assert_eq!(user_text(None, 65532, plain), "65532");
}

// Worked by hand: uptime 1000.50 s at 100 ticks per second is 100050 ticks;
// a start at tick 50000 gives 50050 ticks of life; 2500 busy ticks give
// 2500 * 1000 / 50050 = 49 tenths, so 4.9 %. Fault: CPU over the whole
// uptime or over the last interval instead of the process life, no
// truncation to tenths, a process younger than one tick dividing by zero
// or wrapping to a large value, or 150 % not printed whole.
#[test]
fn cpu_and_memory_percent_match_ps() {
    assert_eq!(cpu_tenths(2500, 50_000, 1000.50, 100), 49);
    assert_eq!(cpu_percent(49), 4.9);
    assert_eq!(cpu_tenths(10, 100_060, 1000.50, 100), 0);
    assert_eq!(cpu_tenths(3000, 99_050, 1000.50, 100), 3000);
    assert_eq!(cpu_percent(1505), 150.0);
    assert_eq!(cpu_percent(999), 99.9);
    assert_eq!(memory_percent(524_288, 1_048_576), 50.0);
    assert_eq!(memory_percent(8372, 16_297_084), 0.0);
    assert_eq!(memory_percent(2_000_000, 1_000_000), 99.9);
    assert_eq!(memory_percent(1, 0), 0.0);
}

// Go's rule also cuts `[kworker/0:1-events]` to `0:1-events]`; that is
// copied (reported as a Go oddity). Fault: the name keeps the path, runs of spaces in the command are kept
// (Go splits and joins with one space), or a row without command words is
// listed (Go needs six fields).
#[test]
fn rows_are_read_back_as_go_parses_ps() {
    let row = go_row(
        42,
        "root".into(),
        1.5,
        0.3,
        17312,
        "/usr/bin/example   --flag  ",
    )
    .unwrap();
    assert_eq!(row.name, "example");
    assert_eq!(row.command, "/usr/bin/example --flag");
    assert_eq!(row.mem_rss, 17312);
    assert_eq!(
        go_row(7, "root".into(), 0.0, 0.0, 0, "[kworker/0:1-events]")
            .unwrap()
            .name,
        "0:1-events]",
        "Go cuts a kernel thread's name at its last '/' too"
    );
    assert!(go_row(8, "root".into(), 0.0, 0.0, 0, "   ").is_none());
}

// Fault: processes come out in directory-name order (10 before 9) instead
// of PID order, a process that ends while being read stops the list, or
// a field is taken from the wrong file.
#[test]
fn process_list_reads_a_proc_tree() {
    let dir = TempDir::new("proc");
    dir.write("proc/uptime", "1000.50 7000.00\n");
    dir.write(
        "proc/meminfo",
        "MemTotal:        1000000 kB\nMemFree: 1 kB\n",
    );
    dir.write(
        "passwd",
        "root:x:0:0::/root:/bin/sh\ndemo:x:1000:1000::/home/demo:/bin/sh\n",
    );
    let stat = |comm: &str, busy: u64, start: u64| {
        format!("1 ({comm}) S 0 0 0 0 -1 0 0 0 0 0 {busy} 0 0 0 20 0 1 0 {start} 0 0")
    };
    dir.write("proc/10/stat", &stat("worker", 2500, 50_000));
    dir.write(
        "proc/10/status",
        "Uid:\t1000\t1000\t1000\t1000\nVmRSS:\t250000 kB\n",
    );
    dir.write("proc/10/cmdline", "/opt/demo/worker\0-v\0");
    dir.write("proc/9/stat", &stat("kthreadd", 0, 2));
    dir.write("proc/9/status", "Uid:\t0\t0\t0\t0\n");
    dir.write("proc/9/cmdline", "");
    dir.write("proc/11/cmdline", "ended");
    dir.write("proc/self/stat", "not a pid");
    let paths = ProcPaths {
        proc: dir.0.join("proc"),
        passwd: dir.0.join("passwd"),
        hertz: 100,
    };
    let list = process_list_with(&paths, TextMode::Plain).unwrap();
    assert_eq!(
        list,
        [
            ProcessRow {
                pid: 9,
                name: "[kthreadd]".into(),
                user: "root".into(),
                cpu_pct: 0.0,
                mem_pct: 0.0,
                mem_rss: 0,
                command: "[kthreadd]".into()
            },
            ProcessRow {
                pid: 10,
                name: "worker".into(),
                user: "demo".into(),
                cpu_pct: 4.9,
                mem_pct: 25.0,
                mem_rss: 250_000,
                command: "/opt/demo/worker -v".into()
            },
        ]
    );
}
