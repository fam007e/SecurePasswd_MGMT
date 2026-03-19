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

- **Add/Edit/Delete:** Managed your password repository.
- **Copy Username/Password/TOTP:** One-click clipboard functionality (clears after 30 sec).
- **Import/Export:** CSV data migration.
- **Health Check:** Security audit of your entire database.
- **Theme Toggle:** Switch between light and dark mode.
- **Recovery Codes Toggle:** NEW: Opt-in visibility for 2FA recovery codes.
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

## Mobile Synchronization

SecurePasswd_MGMT allows you to sync your encrypted vault to your mobile device:

1.  Click the **Sync to Mobile** button on the toolbar.
2.  The application will generate a one-time encryption key and start a secure local server.
3.  A **QR Code** will be displayed containing the connection details and the temporary key.
4.  Scan this QR code with your SecurePasswd Mobile app to securely transfer your vault.
5.  All data is protected with **Chacha20-Poly1305** authenticated encryption during transit.

## Import/Export

You can import and export your password data in CSV format.

- **To import:** Click the **Import** button and select a CSV file. If duplicate entries are detected (matching Service + Username), the application will automatically offer conflict resolution options.
- **To export:** Click the **Export** button and choose a location. **WARNING:** Exported files contain unencrypted secrets and should be handled with extreme caution.

## Changing the Theme

You can switch between a light and dark theme by clicking the **Theme** toggle button on the toolbar.
