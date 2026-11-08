#include "healthcheckdialog.h"
#include <QVBoxLayout>
#include <QTreeWidget>
#include <QHeaderView>
#include <QDialogButtonBox>
#include <QMap>
#include <QPointer>
#include <QtConcurrent/QtConcurrent>
#include <QLabel>

extern "C" {
#include "pwned_check.h"
#include "database.h"
}

HealthCheckDialog::HealthCheckDialog(const QVector<GUIPasswordEntry> &entries, QWidget *parent)
    : QDialog(parent), m_entries(entries)
{
    setWindowTitle("Password Health Check");
    setMinimumSize(600, 400);

    qRegisterMetaType<PwnedResult>();
    m_hibpCancel = QSharedPointer<std::atomic_bool>::create(false);

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
    // Check for reused passwords, short passwords, and low entropy
    QMap<QString, QStringList> passwordMap;
    for (const auto &entry : m_entries) {
        PasswordEntry *db_entry = database_get_entry_secure(entry.id);
        if (db_entry) {
            QString password = QString::fromUtf8(db_entry->password);
            if (!password.isEmpty()) {
                // Reuse check
                passwordMap[password].append(entry.service);

                // Length check
                if (password.length() < 16) {
                    addIssue("Short Passwords", entry.service, QString("Password is only %1 characters (recommended: 16+ for high security).").arg(password.length()));
                }

                // Entropy check
                bool hasUpper = false, hasLower = false, hasNumber = false, hasSpecial = false;
                for (const QChar &ch : password) {
                    if (ch.isUpper()) hasUpper = true;
                    else if (ch.isLower()) hasLower = true;
                    else if (ch.isDigit()) hasNumber = true;
                    else if (!ch.isLetterOrNumber()) hasSpecial = true;
                }

                if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
                    QStringList missing;
                    if (!hasUpper) missing << "uppercase";
                    if (!hasLower) missing << "lowercase";
                    if (!hasNumber) missing << "numbers";
                    if (!hasSpecial) missing << "symbols";
                    addIssue("Low Entropy", entry.service, QString("Missing: %1").arg(missing.join(", ")));
                }
            }
            free_password_entries(db_entry, 1);
        }
    }

    for (auto it = passwordMap.constBegin(); it != passwordMap.constEnd(); ++it) {
        if (it.value().size() > 1) {
            addIssue("Reused Passwords", it.value().join(", "), QString("Password is used for %1 services").arg(it.value().size()));
        }
    }
    treeWidget->expandAll();
}

void HealthCheckDialog::startHibpChecks() {
    // Copy entries to pass to the thread
    QVector<GUIPasswordEntry> entriesCopy = m_entries;

    // The worker must never touch `this`: the dialog can be destroyed while
    // the task is still queued or running (SIGSEGV-at-0x0 via freed members,
    // seen in a core dump as runFunctor -> 0x0). Talk to the dialog only
    // through a QPointer, and cancel via a shared atomic the lambda owns by
    // value alongside the dialog.
    QPointer<HealthCheckDialog> self(this);
    QSharedPointer<std::atomic_bool> cancel = m_hibpCancel;
    cancel->store(false, std::memory_order_relaxed);

    // Use a copy of the database context or ensure thread-safe access
    // Note: SQLCipher/SQLite is usually built with threadsafe=1
    QFuture<void> future = QtConcurrent::run([entriesCopy, self, cancel]() {
        for (const auto &entry : entriesCopy) {
            if (cancel->load(std::memory_order_relaxed) || self.isNull()) break;

            PasswordEntry *db_entry = database_get_entry_secure(entry.id);
            if (db_entry) {
                const char* password = db_entry->password;
                if (password && password[0] != '\0') {
                    int pwnCount = is_password_pwned(password);
                    if (pwnCount > 0) {
                        PwnedResult result = {entry.service, pwnCount};
                        // Thread-safe via queued connection; a destroyed
                        // receiver simply drops the queued event.
                        QMetaObject::invokeMethod(self.data(), "handlePwnedResult", Qt::QueuedConnection, Q_ARG(PwnedResult, result));
                    }
                }
                free_password_entries(db_entry, 1);
            }
        }
    });
    m_hibpWatcher.setFuture(future);
}

HealthCheckDialog::~HealthCheckDialog()
{
    // Stop the worker promptly and sever its access to this dialog. The
    // in-flight is_password_pwned() network call still completes, but the
    // loop breaks before touching anything owned by the destroyed dialog.
    m_hibpCancel->store(true, std::memory_order_relaxed);
    m_hibpWatcher.cancel();
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
