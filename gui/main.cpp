#include <QIcon>
#include <QApplication>
#include <QMessageBox>
#include "passworddialog.h"
#include "mainwindow.h"
#include "key_derivation.h"
#include <sodium.h>
#include <curl/curl.h>
#include <QThread>

int main(int argc, char *argv[]) {
    // Initialize libcurl globally - must be done before any threads use curl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("securepasswd");
    QCoreApplication::setApplicationName("securepasswd");
    app.setWindowIcon(QIcon(":/icons/app_icon.svg"));

    bool authenticated = false;
    while (!authenticated) {
        PasswordDialog passwordDialog;
        if (passwordDialog.exec() == QDialog::Accepted) {
            QString password = passwordDialog.getPassword();
            if (password.isEmpty()) {
                QMessageBox::critical(nullptr, "Error", "Password cannot be empty.");
                continue;
            }

            MainWindow *window = new MainWindow(password);
            if (window->isDatabaseOpen()) {
                authenticated = true;
                window->setAttribute(Qt::WA_DeleteOnClose);
                window->show();
            } else {
                delete window;
                QMessageBox::critical(nullptr, "Login Failed", "Incorrect master password or database error. Please try again.");
                // Rate Limiting: 2 second delay on failure
                QThread::sleep(2);
            }
        } else {
            // User cancelled
            curl_global_cleanup();
            return 0;
        }
    }

    int result = app.exec();
    curl_global_cleanup();
    return result;
}
