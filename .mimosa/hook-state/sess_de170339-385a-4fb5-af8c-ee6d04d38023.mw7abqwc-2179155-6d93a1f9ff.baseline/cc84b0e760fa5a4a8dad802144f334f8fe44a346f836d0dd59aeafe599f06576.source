#include "passwordgeneratordialog.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QDialogButtonBox>

PasswordGeneratorDialog::PasswordGeneratorDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Password Generator Options");
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    QFormLayout *formLayout = new QFormLayout();

    lengthSpinBox = new QSpinBox(this);
    lengthSpinBox->setRange(8, 128);
    lengthSpinBox->setValue(16);
    formLayout->addRow("Length:", lengthSpinBox);

    uppercaseCheckBox = new QCheckBox("Include Uppercase (A-Z)", this);
    uppercaseCheckBox->setChecked(true);
    numbersCheckBox = new QCheckBox("Include Numbers (0-9)", this);
    numbersCheckBox->setChecked(true);
    specialCheckBox = new QCheckBox("Include Special (!@#$%^&*())", this);
    specialCheckBox->setChecked(true);

    mainLayout->addLayout(formLayout);
    mainLayout->addWidget(uppercaseCheckBox);
    mainLayout->addWidget(numbersCheckBox);
    mainLayout->addWidget(specialCheckBox);

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    mainLayout->addWidget(buttonBox);

    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

int PasswordGeneratorDialog::getLength() const
{
    return lengthSpinBox->value();
}

bool PasswordGeneratorDialog::getUseUppercase() const
{
    return uppercaseCheckBox->isChecked();
}

bool PasswordGeneratorDialog::getUseNumbers() const
{
    return numbersCheckBox->isChecked();
}

bool PasswordGeneratorDialog::getUseSpecial() const
{
    return specialCheckBox->isChecked();
}
