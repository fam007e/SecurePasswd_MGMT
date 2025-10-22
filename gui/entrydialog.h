#ifndef ENTRYDIALOG_H
#define ENTRYDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QMessageBox>

#include "passwordentry.h"

#include <QPushButton>

class EntryDialog : public QDialog
{
    Q_OBJECT

public:
    EntryDialog(QWidget *parent = nullptr);

    QString getService() const;
    QString getUsername() const;
    QString getPassword() const;
    QString getTotpSecret() const;

    void setData(const GUIPasswordEntry &entry);

private slots:
    void onGenerateClicked();
    void onAccepted();

private:
    QLineEdit *serviceEdit;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QLineEdit *totpSecretEdit;
    QPushButton *generateButton;
    QDialogButtonBox *buttonBox;
};

#endif // ENTRYDIALOG_H