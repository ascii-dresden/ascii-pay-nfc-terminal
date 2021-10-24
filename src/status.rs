use pnet::datalink::{interfaces, NetworkInterface};
use shadow_rs::shadow;
use std::fmt::Write;

use crate::ServiceResult;

pub fn get_info() -> ServiceResult<String> {
    shadow!(build);

    let mut buffer = String::new();

    writeln!(
        &mut buffer,
        "{} ({})",
        build::PROJECT_NAME,
        build::PKG_VERSION
    )?;

    writeln!(&mut buffer)?;
    writeln!(&mut buffer, "Git")?;

    writeln!(
        &mut buffer,
        "    {}{} ({}) [{}]",
        build::BRANCH,
        if build::GIT_CLEAN { "" } else { "*" },
        build::SHORT_COMMIT,
        build::TAG,
    )?;
    writeln!(&mut buffer, "    {}", build::COMMIT_DATE,)?;

    writeln!(&mut buffer)?;
    writeln!(&mut buffer, "Build")?;
    writeln!(
        &mut buffer,
        "    [{}] at {}",
        build::BUILD_RUST_CHANNEL,
        build::BUILD_TIME
    )?;
    writeln!(&mut buffer, "    {}", build::RUST_VERSION)?;
    writeln!(&mut buffer, "    {}", build::RUST_CHANNEL)?;

    let ipv4_interfaces: Vec<NetworkInterface> = interfaces()
        .into_iter()
        .filter(|e| {
            e.is_up()
                && !e.is_loopback()
                && !e.ips.is_empty()
                && e.ips.iter().any(|ip| ip.is_ipv4())
        })
        .collect();

    let interface = if ipv4_interfaces.is_empty() {
        let all_interfaces: Vec<NetworkInterface> = interfaces()
            .into_iter()
            .filter(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
            .collect();

        all_interfaces
    } else {
        ipv4_interfaces
    };

    if !interface.is_empty() {
        writeln!(&mut buffer)?;
        writeln!(&mut buffer, "Network")?;

        for interface in interface {
            let ips: Vec<String> = interface.ips.iter().map(|ip| ip.to_string()).collect();

            writeln!(
                &mut buffer,
                "    {}({}): {}",
                interface.name,
                interface
                    .mac
                    .map(|m| m.to_string())
                    .as_deref()
                    .unwrap_or("-"),
                ips.join(", ")
            )?;
        }
    }
    Ok(buffer)
}
