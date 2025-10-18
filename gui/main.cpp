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
        MainWindow window(password);
        window.show();

        int result = app.exec();

        return result;

    } else {
        // User cancelled the dialog
        return 0;
    }
}
