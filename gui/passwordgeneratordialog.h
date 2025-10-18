#ifndef PASSWORDGENERATORDIALOG_H
#define PASSWORDGENERATORDIALOG_H

#include <QDialog>
#include <QSpinBox>
#include <QCheckBox>

class PasswordGeneratorDialog : public QDialog
{
    Q_OBJECT

public:
    PasswordGeneratorDialog(QWidget *parent = nullptr);

    int getLength() const;
    bool getUseUppercase() const;
    bool getUseNumbers() const;
    bool getUseSpecial() const;

private:
    QSpinBox *lengthSpinBox;
    QCheckBox *uppercaseCheckBox;
    QCheckBox *numbersCheckBox;
    QCheckBox *specialCheckBox;
};

#endif // PASSWORDGENERATORDIALOG_H
