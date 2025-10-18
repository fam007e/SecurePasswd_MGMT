#include "healthcheckdialog.h"
#include <QVBoxLayout>
#include <QTreeWidget>
#include <QHeaderView>
#include <QDialogButtonBox>
#include <QMap>
#include <QtConcurrent/QtConcurrent>
#include <QLabel>

extern "C" {
#include "pwned_check.h"
}

HealthCheckDialog::HealthCheckDialog(const QVector<GUIPasswordEntry> &entries, QWidget *parent)
    : QDialog(parent), m_entries(entries)
{
    setWindowTitle("Password Health Check");
    setMinimumSize(600, 400);

    qRegisterMetaType<PwnedResult>();

    QVBoxLayout *layout = new QVBoxLayout(this);

    treeWidget = new QTreeWidget(this);
    treeWidget->setHeaderLabels({"Issue", "Details"});
    treeWidget->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    layout->addWidget(treeWidget);

    QLabel* hibpStatusLabel = new QLabel("Checking for pwned passwords...", this);
    layout->addWidget(hibpStatusLabel);

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, this);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    layout->addWidget(buttonBox);

    connect(&m_hibpWatcher, &QFutureWatcher<void>::finished, this, [hibpStatusLabel]() {
        hibpStatusLabel->setText("Pwned password check complete.");
    });

    runLocalChecks();
    startHibpChecks();
}

void HealthCheckDialog::runLocalChecks()
{
    // Check for reused passwords
    QMap<QString, QStringList> passwordMap;
    for (const auto &entry : m_entries) {
        if (!entry.password.isEmpty()) {
            passwordMap[entry.password].append(entry.service);
        }
    }
    for (auto it = passwordMap.constBegin(); it != passwordMap.constEnd(); ++it) {
        if (it.value().size() > 1) {
            addIssue("Reused Passwords", it.value().join(", "), QString("Password is used for %1 services").arg(it.value().size()));
        }
    }

    // Check for weak passwords
    for (const auto &entry : m_entries) {
        const QString &password = entry.password;
        if (password.length() > 0 && password.length() < 12) {
            addIssue("Weak Passwords", entry.service, "Password is too short (less than 12 characters).");
        }

        bool hasUpper = false, hasLower = false, hasNumber = false, hasSpecial = false;
        for (const QChar &ch : password) {
            if (ch.isUpper()) hasUpper = true;
            else if (ch.isLower()) hasLower = true;
            else if (ch.isDigit()) hasNumber = true;
            else if (!ch.isLetterOrNumber()) hasSpecial = true;
        }

        if (password.length() > 0 && (!hasUpper || !hasLower || !hasNumber || !hasSpecial)) {
            addIssue("Low Entropy", entry.service, "Does not contain all character types (upper, lower, number, special).");
        }
    }
    treeWidget->expandAll();
}

void HealthCheckDialog::startHibpChecks() {
    // Copy entries to pass to the thread
    QVector<GUIPasswordEntry> entriesCopy = m_entries;

    QFuture<void> future = QtConcurrent::run([entriesCopy, this]() {
        for (const auto &entry : entriesCopy) {
            if (m_hibpWatcher.isCanceled()) break;
            if (entry.password.isEmpty()) continue;

            int pwnCount = is_password_pwned(entry.password.toUtf8().constData());
            if (pwnCount > 0) {
                PwnedResult result = {entry.service, pwnCount};
                // This is thread-safe because handlePwnedResult is invoked via a queued connection
                QMetaObject::invokeMethod(this, "handlePwnedResult", Qt::QueuedConnection, Q_ARG(PwnedResult, result));
            }
        }
    });
    m_hibpWatcher.setFuture(future);
}

void HealthCheckDialog::handlePwnedResult(PwnedResult result)
{
    addIssue("Pwned Passwords", result.serviceName, QString("Password found %1 times in data breaches.").arg(result.pwnCount));
    treeWidget->expandAll();
}

void HealthCheckDialog::handleHibpFinished() {
    // This slot is connected in the constructor with a lambda
}

void HealthCheckDialog::addIssue(const QString &category, const QString &serviceName, const QString &details)
{
    QTreeWidgetItem *categoryItem = categoryItems.value(category);
    if (!categoryItem) {
        categoryItem = new QTreeWidgetItem(treeWidget, {category});
        categoryItems.insert(category, categoryItem);
    }
    new QTreeWidgetItem(categoryItem, {serviceName, details});
}