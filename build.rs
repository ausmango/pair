use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=assets/pair.ico");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let icon = fs::canonicalize("assets/pair.ico").expect("pair icon exists");
    let icon = icon.to_string_lossy();
    let icon = icon
        .strip_prefix(r"\\?\")
        .unwrap_or(&icon)
        .replace('\\', "/");
    let rc = out.join("pair.rc");
    fs::write(&rc, format!("1 ICON \"{icon}\"\n")).expect("write icon resource");

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let resource = if target_env == "msvc" {
        let resource = out.join("pair.res");
        let status = Command::new("rc.exe")
            .arg("/nologo")
            .arg("/fo")
            .arg(&resource)
            .arg(&rc)
            .status()
            .expect("run rc.exe");
        assert!(status.success(), "rc.exe failed");
        resource
    } else {
        let resource = out.join("pair-icon.o");
        let status = Command::new("windres")
            .args(["-O", "coff"])
            .arg(&rc)
            .arg(&resource)
            .status()
            .expect("run windres");
        assert!(status.success(), "windres failed");
        resource
    };

    println!("cargo:rustc-link-arg-bin=pair={}", resource.display());
}
