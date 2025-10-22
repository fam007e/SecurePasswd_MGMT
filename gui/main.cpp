#include <QIcon>
#include <QApplication>
#include <QMessageBox>
#include "passworddialog.h"
#include "mainwindow.h"
#include "key_derivation.h"
#include <sodium.h>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
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
            return app.exec();
        }
        
        // Set window to delete on close to avoid manual deletion
        window->setAttribute(Qt::WA_DeleteOnClose);
        window->show();

        return app.exec();

    } else {
        // User cancelled the dialog
        return 0;
    }
}
