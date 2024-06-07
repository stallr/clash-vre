/// 给clash内核的tun模式授权
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn grant_permission(core: String) -> anyhow::Result<()> {
    use std::process::Command;
    use tauri::utils::platform::current_exe;

    let path = current_exe()?.with_file_name(core).canonicalize()?;
    let path = path.display().to_string();

    log::debug!("grant_permission path: {path}");

    #[cfg(target_os = "macos")]
    if !getcore_path(&path) {
        Ok(())
    }else{
        let output = {
            let path = path.replace(' ', "\\\\ ");
            let shell = format!("chown root:admin {path}\nchmod +sx {path}");
            let command = format!(r#"do shell script "{shell}" with administrator privileges"#);
            Command::new("osascript")
                .args(vec!["-e", &command])
                .output()?
        };
        if output.status.success() {
            Ok(())
        } else {
            let stderr = std::str::from_utf8(&output.stderr).unwrap_or("");
            anyhow::bail!("{stderr}");
        }
    }

    #[cfg(target_os = "linux")]
    if !getcore_path(&path) {
        Ok(())
    }else{
        let output = {
            let path = path.replace(' ', "\\ "); // 避免路径中有空格
            let shell = format!("setcap cap_net_bind_service,cap_net_admin,cap_dac_override=+ep {path}");

            let sudo = match Command::new("which").arg("pkexec").output() {
                Ok(output) => {
                    if output.stdout.is_empty() {
                        "sudo"
                    } else {
                        "pkexec"
                    }
                }
                Err(_) => "sudo",
            };

            Command::new(sudo).arg("sh").arg("-c").arg(shell).output()?
        };
        if output.status.success() {
            Ok(())
        } else {
            let stderr = std::str::from_utf8(&output.stderr).unwrap_or("");
            anyhow::bail!("{stderr}");
        }
    }
}

#[cfg(target_os = "macos")]
pub fn getcore_path(path: &str) -> bool {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(path) {
        Ok(metadata) => {
            let is_owner_root = metadata.uid() == 0;
            let is_group_admin = metadata.gid() == 80;
            let permissions = metadata.mode();
            let is_setuid_set = permissions & 0o4000 != 0;
            let is_setgid_set = permissions & 0o2000 != 0;
            is_owner_root && is_group_admin && is_setuid_set && is_setgid_set
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
pub fn getcore_path(path: &str) -> bool {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    
    match fs::metadata(path) {
        Ok(metadata) => {
            let is_owner_root = metadata.uid() == 0;
            let is_group_root = metadata.gid() == 0; // 在很多Linux系统上，root组的GID为0
            let permissions = metadata.mode();
            let is_setuid_set = permissions & 0o4000 != 0;
            let is_setgid_set = permissions & 0o2000 != 0;
            is_owner_root && is_group_root && is_setuid_set && is_setgid_set
        }
        Err(_) => false,
    }
}