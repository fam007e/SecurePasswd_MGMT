#include <QIcon>
#include <QApplication>
#include <QMessageBox>
#include "passworddialog.h"
#include "mainwindow.h"
#include "key_derivation.h"
#include <sodium.h>
#include <curl/curl.h>

int main(int argc, char *argv[]) {
    // Initialize libcurl globally - must be done before any threads use curl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("securepasswd");
    QCoreApplication::setApplicationName("securepasswd");
    app.setWindowIcon(QIcon(":/icons/app_icon.svg"));

    PasswordDialog passwordDialog;
    if (passwordDialog.exec() == QDialog::Accepted) {
        QString password = passwordDialog.getPassword();
        if (password.isEmpty()) {
            QMessageBox::critical(nullptr, "Error", "Password cannot be empty.");
            return 1;
        }

        // Key is derived, now we can show the main window
        MainWindow *window = new MainWindow(password);

        // Check if database was opened successfully
        if (!window->isDatabaseOpen()) {
            // Database failed to open, error already shown and quit scheduled
            delete window;
            int result = app.exec();
            curl_global_cleanup();
            return result;
        }

        // Set window to delete on close to avoid manual deletion
        window->setAttribute(Qt::WA_DeleteOnClose);
        window->show();

        int result = app.exec();
        curl_global_cleanup();
        return result;

    } else {
        // User cancelled the dialog
        curl_global_cleanup();
        return 0;
    }
}
