import { invoke } from "@tauri-apps/api/core";

export type SettingsTab =
  | "general"
  | "editor"
  | "themes"
  | "shortcuts"
  | "models"
  | "agents"
  | "about";

export async function openSettingsWindow(tab?: SettingsTab): Promise<void> {
  await invoke("open_settings_window", { tab: tab ?? null, show: true });
}

/** Create the settings webview in the background so the next open is instant. */
export function warmupSettingsWindow(): void {
  void invoke("open_settings_window", { tab: null, show: false });
}
