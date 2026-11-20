mod commands;
mod portable;
mod vault;

use commands::serial::{list_serial_ports, send_serial_command};
use commands::printer::{list_printers, print_raw_esc_pos};
use commands::sidecar::{
    check_port_available, cleanup_all_sidecars, get_sidecar_directories, get_sidecar_status,
    list_embedded_sidecars, list_sidecars, start_sidecar, stop_sidecar, SidecarManager,
};
use commands::system::{exit_app, get_system_info};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Zero C-Drive: keep WebView2 data (localStorage, cache) next to the exe.
    portable::init_webview_data_dir();

    tauri::Builder::default()
        .manage(SidecarManager::default())
        .manage(vault::init_state())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .setup(|app| {
            // Build Context Menu for System Tray
            let open_i = MenuItem::with_id(app, "open", "Open Nora", true, None::<&str>)?;
            let settings_i = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Exit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_i, &settings_i, &quit_i])?;

            // Build Tray Icon with Menu & Click Event
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "settings" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                            let _ = window.emit("navigate-to", "/settings");
                        }
                    }
                    "quit" => {
                        let state = app.state::<SidecarManager>();
                        cleanup_all_sidecars(&state);
                        commands::terminal::cleanup_all();
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_serial_ports,
            send_serial_command,
            list_printers,
            print_raw_esc_pos,
            get_system_info,
            exit_app,
            check_port_available,
            start_sidecar,
            stop_sidecar,
            get_sidecar_status,
            get_sidecar_directories,
            list_embedded_sidecars,
            list_sidecars,
            // --- v1.8.0: vault ---
            commands::vault::vault_status,
            commands::vault::vault_create,
            commands::vault::vault_unlock,
            commands::vault::vault_lock,
            commands::vault::vault_set,
            commands::vault::vault_delete,
            commands::vault::vault_list,
            commands::vault::vault_has,
            commands::vault::vault_change_master,
            commands::vault::vault_set_auto_lock,
            commands::vault::vault_export_backup,
            commands::vault::vault_import_backup,
            // --- v1.8.0: remote FTP/FTPS/SFTP + transfer queue ---
            commands::remote::remote_connect,
            commands::remote::remote_disconnect,
            commands::remote::remote_capabilities,
            commands::remote::remote_list,
            commands::remote::remote_stat,
            commands::remote::remote_mkdir,
            commands::remote::remote_rename,
            commands::remote::remote_delete,
            commands::remote::remote_chmod,
            commands::remote::remote_read_file,
            commands::remote::remote_write_file,
            commands::remote::remote_hash,
            commands::remote::ssh_common::ssh_trust_host,
            commands::remote::transfer::transfer_enqueue,
            commands::remote::transfer::transfer_cancel,
            commands::remote::transfer::transfer_list,
            commands::remote::transfer::transfer_set_concurrency,
            commands::remote::transfer::transfer_clear_finished,
            // --- v1.8.0: local git snapshots ---
            commands::snapshot::snapshot_init,
            commands::snapshot::snapshot_commit,
            commands::snapshot::snapshot_log,
            commands::snapshot::snapshot_diff,
            commands::snapshot::snapshot_restore_file,
            commands::snapshot::snapshot_list_files,
            commands::snapshot::snapshot_tag,
            commands::snapshot::snapshot_list_tags,
            commands::snapshot::snapshot_read_file,
            // --- v1.8.0: hashing / zip ---
            commands::fsutil::fs_cancel,
            commands::fsutil::fs_hash_file,
            commands::fsutil::fs_hash_tree,
            commands::fsutil::fs_compare_trees,
            commands::fsutil::zip_create,
            commands::fsutil::zip_extract,
            // --- v1.9.0: local text file io ---
            commands::fsio::fs_stat,
            commands::fsio::fs_read_text,
            commands::fsio::fs_write_text,
            // --- local file manager ops ---
            commands::fsops::fs_list_drives,
            commands::fsops::fs_list_dir,
            commands::fsops::fs_mkdir,
            commands::fsops::fs_rename,
            commands::fsops::fs_copy,
            commands::fsops::fs_delete,
            // --- v1.8.0: terminal audit ---
            commands::terminal::audit::terminal_audit_list,
            // --- v1.8.0: guarded SSH terminal + exec ---
            commands::terminal::pty::terminal_open,
            commands::terminal::pty::terminal_write,
            commands::terminal::pty::terminal_resize,
            commands::terminal::pty::terminal_close,
            commands::terminal::pty::terminal_set_policy,
            commands::terminal::pty::terminal_list,
            commands::terminal::exec::exec_run,
            commands::terminal::exec::exec_cancel
        ])
        .run(tauri::generate_context!())
        .expect("error while running nora desktop application");
}
