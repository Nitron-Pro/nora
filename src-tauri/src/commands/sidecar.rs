use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::State;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// Flag to hide terminal console window on Windows
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Default)]
pub struct SidecarManager(pub Mutex<HashMap<String, Child>>);

#[derive(Debug, Serialize, Deserialize)]
pub struct SidecarStatus {
    pub name: String,
    pub running: bool,
    pub pid: Option<u32>,
    pub message: String,
}

/// Check if a specific TCP port is free on localhost
#[tauri::command]
pub fn check_port_available(port: u16) -> Result<bool, String> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generic Sidecar starter: starts any external binary/executable
/// Works for Python, Go, Node, C++ binaries
#[tauri::command]
pub fn start_sidecar(
    name: String,
    command: String,
    args: Vec<String>,
    working_dir: Option<String>,
    state: State<'_, SidecarManager>,
) -> Result<SidecarStatus, String> {
    let mut processes = state.0.lock().map_err(|e| e.to_string())?;

    // If already running, check if process is still alive
    if let Some(child) = processes.get_mut(&name) {
        match child.try_wait() {
            Ok(None) => {
                return Ok(SidecarStatus {
                    name: name.clone(),
                    running: true,
                    pid: Some(child.id()),
                    message: "Process is already running".to_string(),
                });
            }
            Ok(Some(_)) | Err(_) => {
                // Process terminated, remove it from map
                processes.remove(&name);
            }
        }
    }

    let mut cmd = Command::new(&command);
    cmd.args(&args);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    // Hide console window on Windows
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            processes.insert(name.clone(), child);
            Ok(SidecarStatus {
                name,
                running: true,
                pid: Some(pid),
                message: "Sidecar started successfully".to_string(),
            })
        }
        Err(e) => Err(format!("Failed to start sidecar '{}': {}", command, e)),
    }
}

/// Stop a running sidecar by name
#[tauri::command]
pub fn stop_sidecar(
    name: String,
    state: State<'_, SidecarManager>,
) -> Result<SidecarStatus, String> {
    let mut processes = state.0.lock().map_err(|e| e.to_string())?;

    if let Some(mut child) = processes.remove(&name) {
        let _ = child.kill();
        let _ = child.wait();
        Ok(SidecarStatus {
            name,
            running: false,
            pid: None,
            message: "Sidecar stopped".to_string(),
        })
    } else {
        Ok(SidecarStatus {
            name,
            running: false,
            pid: None,
            message: "Sidecar was not active".to_string(),
        })
    }
}

/// Query status of a sidecar by name
#[tauri::command]
pub fn get_sidecar_status(
    name: String,
    state: State<'_, SidecarManager>,
) -> Result<SidecarStatus, String> {
    let mut processes = state.0.lock().map_err(|e| e.to_string())?;

    if let Some(child) = processes.get_mut(&name) {
        match child.try_wait() {
            Ok(None) => Ok(SidecarStatus {
                name,
                running: true,
                pid: Some(child.id()),
                message: "Running".to_string(),
            }),
            Ok(Some(exit_code)) => {
                processes.remove(&name);
                Ok(SidecarStatus {
                    name,
                    running: false,
                    pid: None,
                    message: format!("Exited with code: {}", exit_code),
                })
            }
            Err(e) => {
                processes.remove(&name);
                Ok(SidecarStatus {
                    name,
                    running: false,
                    pid: None,
                    message: format!("Error checking status: {}", e),
                })
            }
        }
    } else {
        Ok(SidecarStatus {
            name,
            running: false,
            pid: None,
            message: "Not running".to_string(),
        })
    }
}

/// Stop and clean up all active sidecars (called automatically during app exit)
pub fn cleanup_all_sidecars(state: &SidecarManager) {
    if let Ok(mut processes) = state.0.lock() {
        for (name, mut child) in processes.drain() {
            println!("Cleaning up sidecar process: {}", name);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
