#ifndef PASSWORDDIALOG_H
#define PASSWORDDIALOG_H

#include <QDialog>

class QLineEdit;
class QDialogButtonBox;

class PasswordDialog : public QDialog {
    Q_OBJECT

public:
    explicit PasswordDialog(QWidget *parent = nullptr);
    QString getPassword() const;

private:
    QLineEdit *passwordEdit;
    QDialogButtonBox *buttonBox;
};

#endif // PASSWORDDIALOG_H
