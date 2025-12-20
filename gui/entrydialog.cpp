#include "entrydialog.h"
#include "passwordgeneratordialog.h"
#include <QFormLayout>
#include <QHBoxLayout>
#include <QDialogButtonBox>
#include <QSettings>
#include <QLabel>
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
    recoveryCodesEdit = new QTextEdit(this);
    recoveryCodesEdit->setAcceptRichText(false);
    recoveryCodesEdit->setPlaceholderText("Paste 2FA recovery codes here...");

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

    recoveryCodesLabel = new QLabel("Recovery Codes:", this);
    formLayout->addRow(recoveryCodesLabel, recoveryCodesEdit);

    QSettings settings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    bool enabled = settings.value("recovery_codes_enabled", false).toBool();
    recoveryCodesLabel->setVisible(enabled);
    recoveryCodesEdit->setVisible(enabled);

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    formLayout->addWidget(buttonBox);

    connect(generateButton, &QPushButton::clicked, this, &EntryDialog::onGenerateClicked);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &EntryDialog::onAccepted);
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

void EntryDialog::onAccepted()
{
    // Validate required fields
    if (serviceEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Service name is required.");
        return;
    }

    if (usernameEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Username is required.");
        return;
    }

    // At least password or TOTP must be provided
    if (passwordEdit->text().isEmpty() && totpSecretEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "At least a password or TOTP secret must be provided.");
        return;
    }

    // Validation passed
    accept();
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

QString EntryDialog::getRecoveryCodes() const
{
    return recoveryCodesEdit->toPlainText();
}

void EntryDialog::setData(const GUIPasswordEntry &entry)
{
    serviceEdit->setText(entry.service);
    usernameEdit->setText(entry.username);
    passwordEdit->setText(entry.password);
    totpSecretEdit->setText(entry.totpSecret);
    recoveryCodesEdit->setPlainText(entry.recoveryCodes);
}
