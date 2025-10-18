#include "passworddialog.h"
#include <QLineEdit>
#include <QDialogButtonBox>
#include <QVBoxLayout>
#include <QLabel>

PasswordDialog::PasswordDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Enter Master Password");

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *label = new QLabel("Please enter your master password:");
    layout->addWidget(label);

    passwordEdit = new QLineEdit;
    passwordEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(passwordEdit);

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    layout->addWidget(buttonBox);

    connect(buttonBox, &QDialogButtonBox::accepted, this, &PasswordDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &PasswordDialog::reject);
}

QString PasswordDialog::getPassword() const {
    return passwordEdit->text();
}
