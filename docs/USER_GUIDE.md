# SecurePasswd_MGMT GUI User Guide

This guide provides a detailed walkthrough of the features of the SecurePasswd_MGMT graphical user interface (GUI).

## Introduction

The SecurePasswd_MGMT GUI provides a user-friendly interface for managing your passwords and two-factor authentication (TOTP) secrets. It offers all the functionality of the CLI in a graphical environment.

## First Time Setup

When you launch the application for the first time, you will be prompted to create a new master password. This password will be used to encrypt your password database. Choose a strong and memorable password.

## Main Window

The main window is divided into the following sections:

- **Password List:** A list of all your saved password entries. You can select an entry to view its details.
- **Toolbar:** A row of icons for common actions. The toolbar is icon-only for a clean, modern aesthetic.
- **2FA Recovery Codes:** A list of one-time recovery codes for the selected entry.
- **TOTP Display:** A section that displays the TOTP code for the selected entry, along with a progress bar indicating the time until the next code is generated.

### Toolbar Actions

The toolbar uses icons for all major functions (hover for tooltips):

- **Add/Edit/Delete:** Manage your password repository.
- **Copy Username/Password/TOTP:** One-click clipboard functionality (clears after 30 sec).
- **Import/Export:** CSV data migration.
- **Health Check:** Security audit of your entire database.
- **Vault Sync:** Bidirectional synchronization with the Android companion app.
- **OpenPGP Keys:** Manage armored public and secret GPG keys.
- **Color Palette:** Select between Nord, Dracula, and Solarized palettes.
- **Theme Menu:** Choose between Follow System, Light, and Dark modes.
- **Recovery Codes Toggle:** Opt-in visibility for 2FA recovery codes.
- **Exit:** Securely close the application.

## Adding a New Entry

1.  Click the **Add** button on the toolbar.
2.  In the dialog that appears, fill in the following fields:
    - **Service:** The name of the service (e.g., "Google", "GitHub").
    - **Username:** Your username for the service.
    - **Password:** The password for the service. You can use the **Generate** button to create a strong password.
    - **TOTP Secret:** The TOTP secret provided by the service for two-factor authentication.
3.  Click **OK** to save the new entry.

## Editing an Entry

1.  Select the entry you want to edit from the password list.
2.  Click the **Edit** button on the toolbar.
3.  In the dialog that appears, modify the fields you want to change.
4.  Click **OK** to save the changes.

## Deleting an Entry

1.  Select the entry you want to delete from the password list.
2.  Click the **Delete** button on the toolbar.
3.  A confirmation dialog will appear. Click **Yes** to confirm the deletion.

## Copying Credentials

For security, copied credentials will be cleared from the clipboard after 30 seconds.

- **To copy a username:** Select an entry and click the **Copy Username** button.
- **To copy a password:** Select an entry and click the **Copy Password** button.
- **To copy a TOTP code:** Select an entry and click the **Copy TOTP** button.

## Password Generator

The built-in password generator helps you create strong, random passwords.

1.  Click the **Password Generator** button on the toolbar (or the **Generate** button in the "Add/Edit Entry" dialog).
2.  In the dialog, you can specify the length and character types to include in the password.
3.  Click **Generate** to create a new password.
4.  Click **Copy** to copy the generated password to the clipboard.

## Password Health Check

The password health check feature analyzes your passwords for weaknesses.

1.  Click the **Health Check** button on the toolbar.
2.  The dialog will display a list of potential issues with your passwords, such as:
    - **Reused Passwords:** Passwords that are used for multiple services.
    - **Short Passwords:** Passwords that are shorter than the recommended length.
    - **Low Entropy Passwords:** Passwords that are missing character types (uppercase, lowercase, numbers, symbols).
    - **Pwned Passwords:** Passwords that have been found in known data breaches (requires an internet connection).

## Searching for Entries

Rapidly find your accounts using the global search features:

### GUI Search
- A dedicated **Search Bar** is available at the top of the main window.
- As you type, the list of entries filters in real-time to match services or usernames.
- Clear the search bar to return to the full list.
- **Shortcut:** Press `Ctrl+F` to quickly focus the search bar.

### CLI Search
- **Interactive:** Use the `[s]earch` menu option.
- **Direct:** Run the application with the `-s` or `--search` flag:
  ```bash
  ./securepasswd_cli --search "GitHub"
  ```

## Two-Way Mobile Synchronization

SecurePasswd_MGMT synchronizes your vault **bidirectionally** with the Android companion app over your local network:

1.  Click the **Sync** button on the toolbar.
2.  Choose your network interface if several are available (and optionally set the **Port**, default 33261).
3.  A **QR code** appears containing a one-time 512-bit pairing secret — scan it with the mobile app.
4.  After an authenticated handshake, the mobile sends its vault snapshot; the desktop merges it (newer changes win, deletions propagate) and sends the merged vault back. Both devices end up identical.
5.  Your stored **OpenPGP keys** are exchanged and merged in the same session.
6.  A summary shows exactly what changed: `Added X · Updated Y · Deleted Z · Conflicts W`.
7.  All traffic is end-to-end encrypted (X25519 + ChaCha20-Poly1305); the pairing secret is valid for that session only and never stored.

## Import/Export

You can import and export your password data in CSV format.

- **To import:** Click the **Import** button and select a CSV file. If duplicate entries are detected (matching Service + Username), the application will automatically offer conflict resolution options.
- **To export:** Click the **Export** button and choose a location. **WARNING:** Exported files contain unencrypted secrets and should be handled with extreme caution.

## Themes and Color Palettes

- The **palette button** (paint icon) switches between three curated color families: **Nord** (default), **Dracula**, and **Solarized** — each has dark and light variants.
- The **theme button** (moon/sun icon) opens a menu with **Follow System**, **Light**, and **Dark**. Follow System tracks your OS appearance live.
- The **OpenPGP Keys** button opens the key manager (see below).

## OpenPGP Keys

Store armored GPG keys inside the encrypted vault:

1.  Click the **OpenPGP Keys** button on the toolbar.
2.  Paste your armored key block and fill in a label (the identifier used for sync), email, and key ID.
3.  Keys participate in 2-way sync like password entries; deleting one records a tombstone so the removal propagates.
4.  Use **Copy Public Key** to share your public key; secret keys never leave the vault in plaintext.

## Keyboard Shortcuts Reference

| Scope | Action | Shortcut |
| :--- | :--- | :--- |
| **Main Window** | Add Entry | `Alt+A` |
| | Edit Selected Entry | `Alt+E` or `Enter` / Double-Click on entry |
| | Delete Selected Entry | `Alt+D` or `Delete` key on list |
| | Copy Username | `Alt+U` |
| | Copy Password | `Alt+P` |
| | Copy TOTP Code | `Alt+T` |
| | Focus Search Bar | `Ctrl+F` |
| | Clear Search & Focus List | `Esc` (in Search Bar) |
| | Health Check | `Alt+H` |
| | OpenPGP Keys | `Alt+K` |
| | Change Master Password | `Alt+S` |
| | Import CSV | `Alt+I` |
| | Export CSV | `Alt+X` |
| | Sync to Mobile | `Alt+M` |
| | Theme Menu (System / Light / Dark) | `Alt+Shift+T` |
| | Color Palette Menu | `Alt+Shift+P` |
| | Toggle Recovery Codes View | `Alt+R` |
| | Mark Recovery Code as Used | `Alt+Shift+M` |
| | Exit Application | `Alt+Q` |
| **Add/Edit Entry** | Generate Password | `Alt+G` |
| **OpenPGP Keys** | Save / Update Key | `Ctrl+S` or `Alt+S` |
| | New Key / Clear Form | `Ctrl+N` or `Alt+N` |
| | Copy Public Key | `Ctrl+Shift+C` or `Alt+C` |
| | Delete Key | `Delete` key on list or `Alt+D` |
| **Vault Sync** | Copy Sync Code | `Ctrl+C` |
| **Password Generator**| Jump to Length / Toggles | `Alt+L`, `Alt+U`, `Alt+N`, `Alt+S` |
