#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    if let Err(error) = run() {
        #[cfg(target_os = "windows")]
        let _ = error;
        #[cfg(not(target_os = "windows"))]
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn run() -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;

    let launcher = std::env::current_exe()?;
    let cli = launcher.with_file_name("remora-link.exe");
    if !cli.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Remora Link executable not found at {}", cli.display()),
        ));
    }

    let mut command = std::process::Command::new(cli);
    command
        .arg("serve")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    command.spawn()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn run() -> Result<(), &'static str> {
    Err("remora-link-startup is only used by Windows autostart")
}
