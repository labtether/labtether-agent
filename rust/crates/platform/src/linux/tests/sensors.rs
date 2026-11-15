//! Temperature, interface and PATH tests on a made-up sysfs tree and
//! hand-built netlink messages.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use super::TempDir;
use crate::linux::command_exists;
use crate::linux::netid::{Nic, choose_host_ip, primary_mac};
use crate::linux::netlink::{RTM_NEWADDR, RTM_NEWLINK, interfaces_from, messages};
use crate::linux::sampler::{Sampler, SysPaths};
use crate::linux::temperature::{SensorReading, parse_sysfs_value, read_celsius, select_preferred};

fn reading(key: &str, celsius: f64) -> SensorReading {
    SensorReading {
        key: key.into(),
        celsius,
    }
}

// Fault: the disk or ambient sensor is shown instead of the CPU, or a
// broken sensor (325 °C, -80 °C) becomes the host temperature.
#[test]
fn preferred_sensor_is_the_cpu_and_implausible_values_are_dropped() {
    let readings = [
        reading("nvme_composite", 43.2),
        reading("coretemp_package_id_0", 61.7),
        reading("ambient", 27.0),
    ];
    assert_eq!(
        select_preferred(&readings),
        Some((61.7, "coretemp_package_id_0"))
    );
    // A hotter disk does not beat the CPU; among equals the hottest wins.
    let hot_disk = [
        reading("nvme_composite", 70.0),
        reading("k10temp_tctl", 41.0),
        reading("coretemp_core_1", 45.0),
        reading("k10temp_tccd1", 60.0),
    ];
    assert_eq!(select_preferred(&hot_disk), Some((45.0, "coretemp_core_1")));
    let broken = [
        reading("coretemp_package_id_0", 325.0),
        reading("coretemp_core_0", -80.0),
    ];
    assert_eq!(select_preferred(&broken), None);
    assert_eq!(parse_sysfs_value("52345\n"), Some(52.345));
    assert_eq!(parse_sysfs_value("56.2"), Some(56.2));
    assert_eq!(parse_sysfs_value("n/a"), None);
}

fn hwmon(dir: &TempDir, index: u32, name: &str, sensors: &[(&str, &str, Option<&str>)]) {
    dir.write(
        &format!("sys/class/hwmon/hwmon{index}/name"),
        &format!("{name}\n"),
    );
    for (input, value, label) in sensors {
        dir.write(&format!("sys/class/hwmon/hwmon{index}/{input}"), value);
        if let Some(label) = label {
            let base = input.split('_').next().unwrap();
            dir.write(&format!("sys/class/hwmon/hwmon{index}/{base}_label"), label);
        }
    }
}

// Fault: the sensor rules differ from Go's, so the two agents report a
// different temperature for the same host.
#[test]
fn temperature_uses_labels_and_falls_back_like_go() {
    let dir = TempDir::new("temp");
    let sys = dir.0.join("sys");
    // Nothing readable: no value, and an error to log once.
    assert!(read_celsius(&sys).is_err());

    hwmon(
        &dir,
        0,
        "nvme",
        &[("temp1_input", "48850\n", Some("Composite\n"))],
    );
    hwmon(
        &dir,
        1,
        "coretemp",
        &[("temp1_input", "41000\n", Some("Package id 0\n"))],
    );
    dir.write("sys/class/thermal/thermal_zone0/temp", "70000\n");
    assert_eq!(
        read_celsius(&sys),
        Ok(41.0),
        "CPU priority beats a hotter disk"
    );

    // Fault: one sensor that cannot be read (here its input is a directory,
    // which fails even for root) threw away the other readings, so the
    // hottest file of any kind (the 70 °C thermal zone) was reported in
    // place of the CPU's.
    fs::create_dir_all(sys.join("class/hwmon/hwmon1/temp2_input")).unwrap();
    assert_eq!(read_celsius(&sys), Ok(41.0), "CPU still chosen");
}

// Fault: a VM without sensors gets a temperature, or a host whose sensor
// stops working loses its last value or logs the failure every sample.
#[test]
fn sampler_keeps_the_last_temperature_and_reports_a_failure_once() {
    let dir = TempDir::new("temp-cache");
    let paths = SysPaths {
        proc_stat: dir.0.join("missing"),
        proc_meminfo: dir.0.join("missing"),
        proc_net_dev: dir.0.join("missing"),
        root: dir.0.clone(),
        sys: dir.0.join("sys"),
    };
    let mut none = Sampler::new(paths.clone());
    let (sample, warning) = none.collect(Instant::now());
    assert_eq!(sample.temp_celsius, None, "no sensor: no temperature sent");
    assert!(warning.is_some());

    hwmon(
        &dir,
        0,
        "k10temp",
        &[("temp1_input", "44000\n", Some("Tctl\n"))],
    );
    let mut sampler = Sampler::new(paths);
    let start = Instant::now();
    assert_eq!(sampler.collect(start).0.temp_celsius, Some(44.0));
    fs::remove_dir_all(dir.0.join("sys")).unwrap();
    let (cached, warning) = sampler.collect(start + Duration::from_secs(10));
    assert_eq!(
        (cached.temp_celsius, warning.is_none()),
        (Some(44.0), true),
        "not read again yet"
    );
    let (kept, warning) = sampler.collect(start + Duration::from_secs(31));
    assert_eq!(kept.temp_celsius, Some(44.0), "the last good value stays");
    assert!(warning.is_some(), "the first failure is reported");
    let (_, warning) = sampler.collect(start + Duration::from_secs(62));
    assert!(warning.is_none(), "the same failure is not reported again");
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

// Fault: the Hub shows a Tailscale or Docker address as the device address,
// or Wake-on-LAN gets a bridge's MAC. Cases from Go's netid tests.
#[test]
fn lan_address_and_mac_are_chosen_like_go() {
    let c = |iface: &str, addr: &str| (iface.to_owned(), ip(addr));
    let tailnet_first = [
        c("Tailscale", "100.101.102.103"),
        c("docker0", "172.17.0.1"),
        c("Ethernet", "fe80::1"),
        c("Ethernet", "192.0.2.10"),
        c("Ethernet", "169.254.3.4"),
    ];
    assert_eq!(choose_host_ip(&tailnet_first, None), "192.0.2.10");
    let private = [
        c("tailscale0", "100.64.0.9"),
        c("br-1a2b", "172.18.0.1"),
        c("ens18", "10.0.0.5"),
    ];
    assert_eq!(choose_host_ip(&private, None), "10.0.0.5");
    assert_eq!(choose_host_ip(&private, Some(ip("10.0.0.5"))), "10.0.0.5");
    assert_eq!(choose_host_ip(&private[..1], None), "100.64.0.9");

    let nic = |name: &str, mac: &[u8], up: bool, ips: &[&str]| Nic {
        name: name.into(),
        mac: mac.to_vec(),
        up,
        loopback: name == "lo",
        ips: ips.iter().map(|text| ip(text)).collect(),
    };
    let nics = [
        nic("lo", &[], true, &["127.0.0.1"]),
        nic(
            "docker0",
            &[2, 0x42, 0xac, 0x11, 0, 1],
            true,
            &["172.17.0.1"],
        ),
        nic("enp3s0", &[2, 0, 0, 0, 0, 1], true, &["192.0.2.10"]),
        nic("eno1", &[2, 0, 0, 0, 0, 2], false, &[]),
    ];
    assert_eq!(
        primary_mac(&nics, Some(ip("192.0.2.10"))),
        "02:00:00:00:00:01"
    );
    assert_eq!(primary_mac(&nics, None), "02:00:00:00:00:01");
    assert_eq!(primary_mac(&nics[..2], None), "");
}

fn netlink_message(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = 16 + body.len();
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&0x2u16.to_ne_bytes());
    out.extend_from_slice(&1u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u16::try_from(4 + value.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn link(index: i32, flags: u32, name: &str, mac: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8, 0, 1, 0];
    body.extend_from_slice(&index.to_ne_bytes());
    body.extend_from_slice(&flags.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    body.extend(attr(1, mac));
    body.extend(attr(3, format!("{name}\0").as_bytes()));
    netlink_message(RTM_NEWLINK, &body)
}

fn address(index: i32, family: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = vec![family, 24, 0, 0];
    body.extend_from_slice(&index.to_ne_bytes());
    for (kind, value) in attrs {
        body.extend(attr(*kind, value));
    }
    netlink_message(RTM_NEWADDR, &body)
}

// Fault: the netlink reader takes the wrong attribute (the peer address of
// a point-to-point link, a zero MAC) or pairs an address with the wrong
// interface, so the Hub shows a wrong address or Wake-on-LAN MAC.
#[test]
fn netlink_messages_give_interfaces_like_go() {
    let mut buffer = link(1, 0x9, "lo", &[0; 6]);
    buffer.extend(link(2, 0x1, "eth0", &[2, 0, 0, 0, 0, 1]));
    let links: Vec<Vec<u8>> = messages(&buffer).iter().map(|m| m.2.to_vec()).collect();
    let mut buffer = address(2, 2, &[(1, &[192, 0, 2, 99]), (2, &[192, 0, 2, 10])]);
    buffer.extend(address(1, 2, &[(1, &[127, 0, 0, 1]), (2, &[127, 0, 0, 1])]));
    let v6 = ip("2001:db8::10");
    let IpAddr::V6(v6_addr) = v6 else {
        unreachable!()
    };
    buffer.extend(address(2, 10, &[(1, &v6_addr.octets())]));
    let addrs: Vec<Vec<u8>> = messages(&buffer).iter().map(|m| m.2.to_vec()).collect();
    let links: Vec<&[u8]> = links.iter().map(Vec::as_slice).collect();
    let addrs: Vec<&[u8]> = addrs.iter().map(Vec::as_slice).collect();
    let nics = interfaces_from(&links, &addrs);
    assert_eq!(nics.len(), 2);
    assert_eq!(
        (
            nics[0].name.as_str(),
            nics[0].loopback,
            nics[0].mac.is_empty()
        ),
        ("lo", true, true)
    );
    assert_eq!(nics[1].name, "eth0");
    assert!(nics[1].up && !nics[1].loopback);
    assert_eq!(nics[1].mac, vec![2, 0, 0, 0, 0, 1]);
    assert_eq!(
        nics[1].ips,
        vec![ip("192.0.2.10"), v6],
        "IFA_LOCAL first, v4 then v6"
    );
}

// Fault: `tailscale_installed` is true for a file that cannot run, or a
// later PATH entry is never searched.
#[test]
fn command_lookup_follows_go_rules() {
    let dir = TempDir::new("path");
    let bin = dir.write("bin/tool", "#!/bin/sh\n");
    let plain = dir.write("plain/tool", "data\n");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
    let bin_dir = dir.0.join("bin").display().to_string();
    let plain_dir = dir.0.join("plain").display().to_string();
    assert!(command_exists("tool", &format!("/nonexistent:{bin_dir}")));
    assert!(!command_exists("missing", &bin_dir));
    assert!(!command_exists("tool", &plain_dir), "not executable");
}
