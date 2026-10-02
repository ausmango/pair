#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod ui;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--internal-gui"] {
        ui::run(false);
        return;
    }
    if !args.is_empty() {
        attach_console();
    }
    if let Err(error) = command(&args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn command(args: &[String]) -> Result<(), String> {
    use pair::cli::{self, Invocation, Request};
    let request = match cli::parse(args)? {
        Invocation::Help => {
            println!("{}", cli::HELP);
            return Ok(());
        }
        Invocation::Install => {
            println!("{}", cli::install()?);
            return Ok(());
        }
        Invocation::Application(request) => request,
    };
    let directory = cli::directory()?;
    if let Ok(response) = cli::send(&directory, &request) {
        return output(response, !args.is_empty());
    }
    if request == Request::Status {
        println!("Pair is not running. Run pair open, pair host, or pair connect <computer>.");
        return Ok(());
    }
    if request == Request::Nearby {
        let saved = std::fs::read(pair::persistence::default_path()?)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let mut devices = cli::nearby()?;
        if let Some(own_id) = saved.as_ref().and_then(|data| data["device_id"].as_str()) {
            devices.retain(|device| device.id != own_id);
        }
        if devices.is_empty() {
            println!("Device not discovered. Open Pair in host mode on the other computer.");
        }
        for device in devices {
            let trusted = saved.as_ref().is_some_and(|data| {
                data["trusted_host"]["id"].as_str() == Some(&device.id)
                    || data["trusted_peers"].as_array().is_some_and(|peers| {
                        peers
                            .iter()
                            .any(|peer| peer["id"].as_str() == Some(&device.id))
                    })
            });
            println!(
                "{}  {}  {}  {}",
                device.name,
                device.id,
                if trusted { "paired" } else { "not paired" },
                device
                    .addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return Ok(());
    }
    if args.is_empty() {
        ui::run(true);
        return Ok(());
    }
    let mut child = std::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    child
        .arg("--internal-gui")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        child.creation_flags(0x08000000); // CREATE_NO_WINDOW: GUI retains its own window.
    }
    child
        .spawn()
        .map_err(|_| "Could not open Pair.".to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Ok(response) = cli::send(&directory, &request) {
            return output(response, true);
        }
    }
    Err("Pair could not accept the command. Check its window or local control port.".into())
}

fn output(response: pair::cli::Response, print: bool) -> Result<(), String> {
    if !response.ok {
        return Err(response.message);
    }
    if print {
        println!("{}", response.message);
    }
    Ok(())
}

#[cfg(windows)]
fn attach_console() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AttachConsole(process: u32) -> i32;
    }
    // Attach only to the terminal that invoked us; GUI launch creates no console.
    unsafe {
        AttachConsole(u32::MAX);
    }
}
#[cfg(not(windows))]
fn attach_console() {}
