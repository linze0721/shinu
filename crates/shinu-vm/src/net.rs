use shinu_core::{Error, GUEST_BLOCKED_CIDRS, Result, parse_ipv4, parse_ipv4_cidr, parse_net_base};
use uuid::Uuid;

/// A host service that guests may call through the host-side firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAllow {
    pub protocol: String,
    pub port: u16,
    pub destination: Option<String>,
}

/// A private /30 network for each VM. The host owns `.1`, the guest `.2`.
///
/// The pool is daemon-wide: deterministic addresses make restarts idempotent,
/// while rejecting occupied host addresses prevents subnet reuse.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// `SHINU_NET_ENABLE` — "0" and "false" disable guest networking.
    pub enabled: bool,
    /// `SHINU_NET_BASE` — the first two octets of the /16 pool.
    pub base: [u8; 2],
    /// `SHINU_NET_ALLOW` — comma-separated IPv4 CIDRs allowed before the
    /// private-address egress filter. Empty means no private destinations.
    pub allow: Vec<String>,
    /// `SHINU_HOST_ALLOW` — comma-separated `tcp:PORT` or
    /// `tcp:PORT@DESTINATION` (with `tcp` replaced by `udp` as needed).
    ///
    /// Guests may call back into host services through `DNATed` loopback ports;
    /// these ACCEPTs must stay before per-tap DROP rules without racing VM
    /// starts, so `tap_up` keeps them in the daemon-owned input chain.
    pub host_allow: Vec<HostAllow>,
    /// `SHINU_NET_UPLINK` — host interface used for NAT egress.
    pub uplink: String,
}
/// Parses `SHINU_NET_ALLOW` without silently dropping malformed entries.
pub fn parse_net_allow(value: &str) -> Result<Vec<String>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            if parse_ipv4_cidr(entry).is_none() {
                return Err(Error::Invalid(format!(
                    "invalid SHINU_NET_ALLOW entry {entry:?}; expected an IPv4 CIDR such as 10.0.0.0/8"
                )));
            }
            Ok(entry.to_owned())
        })
        .collect()
}

/// Parses `SHINU_HOST_ALLOW` without silently dropping malformed entries.
pub fn parse_host_allow(value: &str) -> Result<Vec<HostAllow>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            let invalid = || {
                Error::Invalid(format!(
                    "invalid SHINU_HOST_ALLOW entry {entry:?}; expected tcp:23000, udp:5353, or tcp:23000@127.0.0.1"
                ))
            };
            let Some((protocol, port_and_destination)) = entry.split_once(':') else {
                return Err(invalid());
            };
            if !matches!(protocol, "tcp" | "udp") {
                return Err(invalid());
            }
            let (port_text, destination) = match port_and_destination.split_once('@') {
                Some((port, destination))
                    if !destination.is_empty() && destination == destination.trim() =>
                {
                    if destination.contains('@') {
                        return Err(invalid());
                    }
                    (port, Some(destination))
                }
                Some(_) => return Err(invalid()),
                None => (port_and_destination, None),
            };
            let port = port_text
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(invalid)?;
            if let Some(destination) = destination
                && parse_ipv4(destination).is_none()
            {
                return Err(invalid());
            }
            Ok(HostAllow {
                protocol: protocol.to_owned(),
                port,
                destination: destination.map(str::to_owned),
            })
        })
        .collect()
}

/// Builds the rule matched by a host callback allowlist entry.
pub(crate) fn host_allow_rule(allow: &HostAllow) -> Vec<String> {
    let mut rule = vec![
        "-i".to_owned(),
        "shinu+".to_owned(),
        "-p".to_owned(),
        allow.protocol.clone(),
    ];
    if let Some(destination) = &allow.destination {
        rule.extend(["-d".to_owned(), destination.clone()]);
    }
    rule.extend([
        "--dport".to_owned(),
        allow.port.to_string(),
        "-j".to_owned(),
        "ACCEPT".to_owned(),
    ]);
    rule
}

/// Builds the input-fence rule for one tap.
pub(crate) fn input_drop_rule(tap: &str) -> Vec<String> {
    vec![
        "-i".to_owned(),
        tap.to_owned(),
        "-j".to_owned(),
        "DROP".to_owned(),
    ]
}

fn default_uplink() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut tokens = output
        .stdout
        .split(|byte| *byte == b' ' || *byte == b'\n' || *byte == b'\t')
        .filter(|token| !token.is_empty());
    while let Some(token) = tokens.next() {
        if token == b"dev" {
            return tokens
                .next()
                .map(|device| String::from_utf8_lossy(device).into_owned());
        }
    }
    None
}

impl NetConfig {
    pub fn from_env() -> Result<Self> {
        let enabled = !std::env::var("SHINU_NET_ENABLE").ok().is_some_and(|value| {
            let value = value.trim();
            value == "0" || value.eq_ignore_ascii_case("false")
        });
        let base = match std::env::var("SHINU_NET_BASE") {
            Ok(value) => parse_net_base(&value).ok_or_else(|| {
                Error::Invalid(format!(
                    "invalid SHINU_NET_BASE={value:?}; expected two octets such as 172.31"
                ))
            })?,
            Err(_) => [172, 31],
        };
        let allow = match std::env::var("SHINU_NET_ALLOW") {
            Ok(value) => parse_net_allow(&value)?,
            Err(_) => Vec::new(),
        };
        let host_allow = match std::env::var("SHINU_HOST_ALLOW") {
            Ok(value) => parse_host_allow(&value)?,
            Err(_) => Vec::new(),
        };
        let uplink = match std::env::var("SHINU_NET_UPLINK") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
            _ if enabled => default_uplink().ok_or_else(|| {
                Error::Invalid(
                    "cannot determine the default uplink; set SHINU_NET_UPLINK".to_owned(),
                )
            })?,
            _ => String::new(),
        };
        Ok(Self {
            enabled,
            base,
            allow,
            host_allow,
            uplink,
        })
    }
}

/// Returns the third octet and /30-aligned fourth-octet base for a space.
/// Fourteen UUID bits provide 16,384 disjoint /30s without a mutable allocator.
pub fn net_slot(id: Uuid) -> (u8, u8) {
    let bytes = id.as_bytes();
    let index = u16::from_be_bytes([bytes[0], bytes[1]]) & 0x3fff;
    let [index_high, index_low] = index.to_be_bytes();
    (
        (index_high << 2) | (index_low >> 6),
        (index_low & 0x3f) << 2,
    )
}

/// Linux interface names have fifteen usable bytes; the ten hex characters
/// after `shinu` leave no room for the kernel's terminating byte.
pub fn tap_name(id: Uuid) -> String {
    format!("shinu{}", &id.simple().to_string()[..10])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSpec {
    pub tap: String,
    pub mac: String,
    pub guest_cidr: String,
    pub gateway: String,
}

/// Derives every guest-facing network value from one UUID and one pool config.
/// Keeping this as one constructor prevents a tap, MAC, and kernel address from
/// silently referring to different spaces after a restart.
pub fn net_spec(id: Uuid, cfg: &NetConfig) -> Option<NetSpec> {
    if !cfg.enabled {
        return None;
    }
    let (third, fourth_base) = net_slot(id);
    let host = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 1
    );
    let guest = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 2
    );
    let bytes = id.as_bytes();
    Some(NetSpec {
        tap: tap_name(id),
        mac: format!(
            "AA:FC:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ),
        guest_cidr: format!("{guest}/30"),
        gateway: host,
    })
}

/// Returns match/action arguments in firewall order. `tap_up` inserts each
/// rule at its final position so retries preserve this ordering.
/// The gateway exception remains first for host access. Named-network peer
/// exceptions must precede the inter-tap fence, which must precede operator
/// allowances so a broad allow cannot bypass tenant isolation.
pub fn egress_rules(tap: &str, gateway: &str, allow: &[String]) -> Vec<Vec<String>> {
    egress_rules_with_peers(tap, gateway, allow, &[])
}

pub(crate) fn peer_rule(tap: &str, peer: &str) -> Vec<String> {
    vec![
        "-i".to_owned(),
        tap.to_owned(),
        "-d".to_owned(),
        format!("{peer}/32"),
        "-j".to_owned(),
        "ACCEPT".to_owned(),
    ]
}

/// Returns one ACCEPT rule for each named-network peer guest address.
/// UUID-derived addresses are scattered through the pool, so each peer gets
/// an explicit /32 exception before the inter-tap and private-destination drops.
pub fn peer_rules(tap: &str, peers: &[String]) -> Vec<Vec<String>> {
    peers.iter().map(|peer| peer_rule(tap, peer)).collect()
}

/// Builds the complete ordered rule list, placing peer exceptions before the
/// inter-tap fence, then operator allowances and private-destination drops.
pub(crate) fn egress_rules_with_peers(
    tap: &str,
    gateway: &str,
    allow: &[String],
    peers: &[String],
) -> Vec<Vec<String>> {
    let mut rules = Vec::with_capacity(2 + peers.len() + allow.len() + GUEST_BLOCKED_CIDRS.len());
    rules.push(vec![
        "-i".to_owned(),
        tap.to_owned(),
        "-d".to_owned(),
        gateway.to_owned(),
        "-j".to_owned(),
        "ACCEPT".to_owned(),
    ]);
    for peer in peers {
        rules.push(peer_rule(tap, peer));
    }
    rules.push(vec![
        "-i".to_owned(),
        tap.to_owned(),
        "-o".to_owned(),
        "shinu+".to_owned(),
        "-j".to_owned(),
        "DROP".to_owned(),
    ]);
    for destination in allow {
        rules.push(vec![
            "-i".to_owned(),
            tap.to_owned(),
            "-d".to_owned(),
            destination.clone(),
            "-j".to_owned(),
            "ACCEPT".to_owned(),
        ]);
    }
    for destination in GUEST_BLOCKED_CIDRS {
        rules.push(vec![
            "-i".to_owned(),
            tap.to_owned(),
            "-d".to_owned(),
            destination.to_owned(),
            "-j".to_owned(),
            "DROP".to_owned(),
        ]);
    }
    rules
}

#[cfg(test)]
mod network_tests {
    use super::{
        HostAllow, NetSpec, egress_rules_with_peers, host_allow_rule, input_drop_rule, net_slot,
        parse_host_allow, parse_net_allow, peer_rules, tap_name,
    };
    use crate::config::vm_config_json;
    use crate::vm::egress_rules;
    use serde_json::Value;
    use shinu_core::Image;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn derives_disjoint_addresses_inside_one_slash_thirty() {
        let id = Uuid::from_bytes([0xab, 0xcd, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (third, fourth_base) = net_slot(id);
        assert_eq!(fourth_base, 52);
        let host = fourth_base + 1;
        let guest = fourth_base + 2;
        assert_eq!(guest - host, 1);
        assert!(host > fourth_base && guest < fourth_base + 4);
        assert_eq!(third, 175);
    }

    #[test]
    fn tap_names_fit_linux_and_include_uuid_identity() {
        let first = tap_name(Uuid::from_bytes([
            0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let second = tap_name(Uuid::from_bytes([
            0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        assert_eq!(first.len(), 15);
        assert_eq!(second.len(), 15);
        assert_ne!(first, second);
    }

    #[test]
    fn vm_config_without_network_enables_dirty_tracking() {
        let actual = vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Void,
            Path::new("/vsock"),
            2,
            128,
            None,
        );
        let legacy = serde_json::json!({
            "boot-source": {
                "kernel_image_path": "/kernel",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/init"
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": "/rootfs",
                "is_root_device": true,
                "is_read_only": false
            }],
            "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": "/vsock" },
            "balloon": { "amount_mib": 0, "deflate_on_oom": true, "stats_polling_interval_s": 1, "free_page_reporting": true },
            "machine-config": { "vcpu_count": 2, "mem_size_mib": 128, "track_dirty_pages": true }
        })
        .to_string();
        assert_eq!(actual, legacy);
    }
    #[test]
    fn vm_config_uses_arch_systemd_init_path() {
        let value: Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Arch,
            Path::new("/vsock"),
            2,
            128,
            None,
        ))
        .expect("valid Firecracker JSON");
        assert_eq!(
            value["boot-source"]["boot_args"],
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/usr/lib/systemd/systemd"
        );
    }

    #[test]
    fn vm_config_network_contains_interface_and_kernel_addresses() {
        let spec = NetSpec {
            tap: "shinu0123456789".to_owned(),
            mac: "AA:FC:12:34:56:78".to_owned(),
            guest_cidr: "172.31.47.54/30".to_owned(),
            gateway: "172.31.47.53".to_owned(),
        };
        let value: Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Void,
            Path::new("/vsock"),
            2,
            128,
            Some(&spec),
        ))
        .expect("valid Firecracker JSON");
        assert_eq!(value["network-interfaces"][0]["iface_id"], "eth0");
        assert_eq!(value["network-interfaces"][0]["host_dev_name"], spec.tap);
        assert_eq!(value["network-interfaces"][0]["guest_mac"], spec.mac);
        let boot_args = value["boot-source"]["boot_args"]
            .as_str()
            .expect("boot args string");
        assert!(boot_args.ends_with(" shinu.ip=172.31.47.54/30 shinu.gw=172.31.47.53"));
    }

    #[test]

    fn parses_network_allow_entries_strictly() {
        assert_eq!(
            parse_net_allow("10.42.0.0/16, 192.168.5.0/24").expect("valid CIDRs"),
            vec!["10.42.0.0/16".to_owned(), "192.168.5.0/24".to_owned()]
        );
        assert!(parse_net_allow("").expect("empty allow list").is_empty());
        assert!(parse_net_allow("10.0.0.0/33").is_err());
        assert!(parse_net_allow("10.0.0.0/8,").is_err());
    }

    #[test]
    fn parses_host_allow_entries_strictly() {
        assert_eq!(
            parse_host_allow("tcp:23000, udp:5353").expect("valid host ports"),
            vec![
                HostAllow {
                    protocol: "tcp".to_owned(),
                    port: 23000,
                    destination: None,
                },
                HostAllow {
                    protocol: "udp".to_owned(),
                    port: 5353,
                    destination: None,
                },
            ]
        );
        assert_eq!(
            parse_host_allow("tcp:23000@127.0.0.1").expect("valid destination"),
            vec![HostAllow {
                protocol: "tcp".to_owned(),
                port: 23000,
                destination: Some("127.0.0.1".to_owned()),
            }]
        );
        assert!(
            parse_host_allow("")
                .expect("empty host allow list")
                .is_empty()
        );
        for malformed in [
            "icmp:23000",
            "tcp",
            "tcp:",
            "tcp:0",
            "tcp:65536",
            "tcp:23000@",
            "tcp:23000@127.0.0.999",
            "tcp:23000@127.0.0.1@127.0.0.2",
            "tcp:23000,",
        ] {
            assert!(
                parse_host_allow(malformed).is_err(),
                "accepted {malformed:?}"
            );
        }
    }

    #[test]
    fn host_allow_rules_match_tap_wildcard_and_optional_destination() {
        assert_eq!(
            host_allow_rule(&HostAllow {
                protocol: "tcp".to_owned(),
                port: 23000,
                destination: None,
            }),
            vec![
                "-i".to_owned(),
                "shinu+".to_owned(),
                "-p".to_owned(),
                "tcp".to_owned(),
                "--dport".to_owned(),
                "23000".to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ]
        );
        assert_eq!(
            host_allow_rule(&HostAllow {
                protocol: "udp".to_owned(),
                port: 5353,
                destination: Some("127.0.0.1".to_owned()),
            }),
            vec![
                "-i".to_owned(),
                "shinu+".to_owned(),
                "-p".to_owned(),
                "udp".to_owned(),
                "-d".to_owned(),
                "127.0.0.1".to_owned(),
                "--dport".to_owned(),
                "5353".to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ]
        );
    }

    #[test]
    fn input_drop_rule_targets_only_the_tap() {
        assert_eq!(
            input_drop_rule("shinu0123456789"),
            vec![
                "-i".to_owned(),
                "shinu0123456789".to_owned(),
                "-j".to_owned(),
                "DROP".to_owned(),
            ]
        );
    }

    #[test]
    fn egress_rules_put_gateway_and_isolation_before_allowlist_and_private_drops() {
        let allow = vec!["10.42.0.0/16".to_owned()];
        let rules = egress_rules("tap0", "172.31.1.1", &allow);
        assert_eq!(rules.len(), 8);
        assert_eq!(
            rules[0],
            vec![
                "-i".to_owned(),
                "tap0".to_owned(),
                "-d".to_owned(),
                "172.31.1.1".to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ]
        );
        assert_eq!(
            rules[1],
            vec![
                "-i".to_owned(),
                "tap0".to_owned(),
                "-o".to_owned(),
                "shinu+".to_owned(),
                "-j".to_owned(),
                "DROP".to_owned(),
            ]
        );
        assert_eq!(rules[2][3], "10.42.0.0/16");
        assert_eq!(rules[2][5], "ACCEPT");
        for (rule, destination) in rules[3..].iter().zip([
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "127.0.0.0/8",
        ]) {
            assert_eq!(rule[3], destination);
            assert_eq!(rule[5], "DROP");
        }
    }

    #[test]
    fn ordered_rules_place_peers_before_intertap_drop_and_allowlist() {
        let allow = vec!["10.42.0.0/16".to_owned()];
        let peers = vec!["172.31.1.2".to_owned(), "172.31.200.6".to_owned()];
        let rules = egress_rules_with_peers("tap0", "172.31.1.1", &allow, &peers);
        assert_eq!(rules[1][3], "172.31.1.2/32");
        assert_eq!(rules[2][3], "172.31.200.6/32");
        assert_eq!(rules[3][1], "tap0");
        assert_eq!(rules[3][3], "shinu+");
        assert_eq!(rules[3][5], "DROP");
        assert_eq!(rules[4][3], "10.42.0.0/16");
        assert_eq!(rules[4][5], "ACCEPT");
        assert_eq!(rules[5][3], "10.0.0.0/8");
        assert_eq!(rules[5][5], "DROP");
    }

    #[test]
    fn global_allow_overlapping_guest_pool_follows_intertap_drop() {
        let allow = vec!["172.31.0.0/16".to_owned()];
        let rules = egress_rules_with_peers("tap0", "172.31.1.1", &allow, &[]);
        let intertap_drop = rules
            .iter()
            .position(|rule| {
                rule[1] == "tap0" && rule[2] == "-o" && rule[3] == "shinu+" && rule[5] == "DROP"
            })
            .expect("per-tap intertap drop");
        let global_allow = rules
            .iter()
            .position(|rule| rule[3] == "172.31.0.0/16" && rule[5] == "ACCEPT")
            .expect("global guest-pool allow");
        assert!(intertap_drop < global_allow);
    }

    #[test]
    fn peer_rules_keep_peer_order_and_use_host_firewall_slash_thirty_twos() {
        let peers = vec!["172.31.1.2".to_owned(), "172.31.200.6".to_owned()];
        assert_eq!(
            peer_rules("tap0", &peers),
            vec![
                vec![
                    "-i".to_owned(),
                    "tap0".to_owned(),
                    "-d".to_owned(),
                    "172.31.1.2/32".to_owned(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                vec![
                    "-i".to_owned(),
                    "tap0".to_owned(),
                    "-d".to_owned(),
                    "172.31.200.6/32".to_owned(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
            ]
        );
    }
}
