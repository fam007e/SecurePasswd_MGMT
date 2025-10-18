#include "entrydialog.h"
#include "passwordgeneratordialog.h"
#include <QFormLayout>
#include <QHBoxLayout>
#include <QDialogButtonBox>
#include <stdlib.h> // For free()

// Need to link against the C password generator
extern "C" {
#include "password_generator.h"
}

EntryDialog::EntryDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Add/Edit Entry");

    QFormLayout *formLayout = new QFormLayout(this);

    serviceEdit = new QLineEdit(this);
    usernameEdit = new QLineEdit(this);
    totpSecretEdit = new QLineEdit(this);

    // Password field with a generate button
    QHBoxLayout *passwordLayout = new QHBoxLayout();
    passwordEdit = new QLineEdit(this);
    passwordEdit->setEchoMode(QLineEdit::Password);
    generateButton = new QPushButton("Generate", this);
    passwordLayout->addWidget(passwordEdit);
    passwordLayout->addWidget(generateButton);

    formLayout->addRow("Service:", serviceEdit);
    formLayout->addRow("Username:", usernameEdit);
    formLayout->addRow("Password:", passwordLayout);
    formLayout->addRow("TOTP Secret (Optional):", totpSecretEdit);

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    formLayout->addWidget(buttonBox);

    connect(generateButton, &QPushButton::clicked, this, &EntryDialog::onGenerateClicked);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void EntryDialog::onGenerateClicked()
{
    PasswordGeneratorDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        char *password = generate_password(dialog.getLength(),
                                           dialog.getUseUppercase(),
                                           dialog.getUseNumbers(),
                                           dialog.getUseSpecial());
        if (password) {
            passwordEdit->setText(password);
            free(password);
        }
    }
}

QString EntryDialog::getService() const
{
    return serviceEdit->text();
}

QString EntryDialog::getUsername() const
{
    return usernameEdit->text();
}

QString EntryDialog::getPassword() const
{
    return passwordEdit->text();
}

QString EntryDialog::getTotpSecret() const
{
    return totpSecretEdit->text();
}

void EntryDialog::setData(const GUIPasswordEntry &entry)
{
    serviceEdit->setText(entry.service);
    usernameEdit->setText(entry.username);
    passwordEdit->setText(entry.password);
    totpSecretEdit->setText(entry.totpSecret);
}