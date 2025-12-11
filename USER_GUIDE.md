# SecurePasswd_MGMT GUI User Guide

This guide provides a detailed walkthrough of the features of the SecurePasswd_MGMT graphical user interface (GUI).

## Introduction

The SecurePasswd_MGMT GUI provides a user-friendly interface for managing your passwords and two-factor authentication (TOTP) secrets. It offers all the functionality of the CLI in a graphical environment.

## First Time Setup

When you launch the application for the first time, you will be prompted to create a new master password. This password will be used to encrypt your password database. Choose a strong and memorable password.

## Main Window

The main window is divided into the following sections:

- **Password List:** A list of all your saved password entries. You can select an entry to view its details.
- **Toolbar:** A row of buttons for common actions.
- **TOTP Display:** A section that displays the TOTP code for the selected entry, along with a progress bar indicating the time until the next code is generated.

### Toolbar Actions

- **Add:** Add a new password entry.
- **Edit:** Edit the selected password entry.
- **Delete:** Delete the selected password entry.
- **Copy Username:** Copy the username of the selected entry to the clipboard.
- **Copy Password:** Copy the password of the selected entry to the clipboard.
- **Copy TOTP:** Copy the TOTP code of the selected entry to the clipboard.
- **Password Generator:** Open the password generator dialog.
- **Health Check:** Open the password health check dialog.
- **Import:** Import password entries from a CSV file.
- **Export:** Export all password entries to a CSV file.
- **Theme:** Switch between light and dark mode.

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

## Import/Export

You can import and export your password data in CSV format.

- **To import:** Click the **Import** button and select a CSV file to import.
- **To export:** Click the **Export** button and choose a location to save the CSV file.

## Changing the Theme

You can switch between a light and dark theme by clicking the **Theme** toggle button on the toolbar.
