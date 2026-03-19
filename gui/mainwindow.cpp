#include "mainwindow.h"
#include "entrydialog.h"
#include "syncdialog.h"
#include "healthcheckdialog.h"
#include "database.h"
#include "totp.h"
#include "platform_paths.h"
#include "passwordentry.h"
#include <csv.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QAction>
#include <QMessageBox>
#include <QFileDialog>
#include <QHeaderView>
#include <QClipboard>
#include <QApplication>
#include <QTimer>
#include <QLabel>
#include <QProgressBar>
#include <QSettings>
#include <QFile>
#include <QDir>
#include <QInputDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QStatusBar>
#include <QListWidget>
#include <vector>

// Forward declaration for CSV callbacks
static void import_field_cb(void *s, size_t len, void *data);
static void import_row_cb(int c, void *data);

// Callbacks for libcsv import
void import_field_cb(void *s, size_t len, void *data) {
    static_cast<QStringList*>(data)->append(QString::fromUtf8((char*)s, (int)len));
}

// Sanitize fields against CSV injection (Formula Injection)
static QString sanitize_csv_field(QString field) {
    if (field.startsWith('=') || field.startsWith('+') || field.startsWith('-') || field.startsWith('@')) {
        return "'" + field;
    }
    return field;
}

static void import_row_cb(int c, void *data) {
    QStringList *fields = static_cast<QStringList*>(data);
    if (fields->count() >= 3) {
        PasswordEntry entry;
        QByteArray service = fields->at(0).toUtf8();
        QByteArray username = fields->at(1).toUtf8();
        QByteArray password = fields->at(2).toUtf8();
        QByteArray totpSecret = (fields->count() >= 4) ? fields->at(3).toUtf8() : QByteArray("");
        QByteArray recoveryCodes = (fields->count() >= 5) ? fields->at(4).toUtf8() : QByteArray("");

        entry.service = (char*)service.constData();
        entry.username = (char*)username.constData();
        entry.password = (char*)password.constData();
        entry.totp_secret = (char*)totpSecret.constData();
        entry.recovery_codes = (char*)recoveryCodes.constData();

        // Identity check for duplicates
        PasswordEntry *existing = database_get_entry_by_identity(entry.service, entry.username);
        if (existing) {
            bool identical = (strcmp(existing->password, entry.password) == 0 &&
                             strcmp(existing->totp_secret, entry.totp_secret) == 0 &&
                             strcmp(existing->recovery_codes, entry.recovery_codes) == 0);

            if (!identical) {
                // For GUI, we might want to prompt, but for batch import we'll update or skip.
                // Here we update to match CLI's "overwrite" capability if we had a dialog.
                // Simple approach for now: update existing.
                entry.id = existing->id;
                database_update_entry(&entry);
            }
            free_password_entries(existing, 1);
        } else {
            database_add_entry(&entry);
        }
    }
    fields->clear();
}

MainWindow::MainWindow(const QString& password, QWidget *parent) : QMainWindow(parent), m_databaseOpen(false), searchBar(nullptr), recoveryCodesEnabled(false) {
    // Use shared platform_paths function
    std::vector<char> dirPath(4096);
    get_config_path(dirPath.data(), dirPath.size());
    QString dbDirPath = QString::fromUtf8(dirPath.data());

    QDir dir(dbDirPath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    QString dbPath = dbDirPath + "/vault.db";

    if (database_open( /* flawfinder: ignore */ dbPath.toUtf8().constData(), password.toUtf8().constData()) != 0) {
        return;
    }

    m_databaseOpen = true;

    QSettings settings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    recoveryCodesEnabled = settings.value("recovery_codes_enabled", false).toBool();

    setupUI();
    refreshEntryList();

    currentTheme = settings.value("theme", "light").toString();
    loadTheme(currentTheme);
}

MainWindow::~MainWindow() {
    database_close();
}

void MainWindow::onImport() {
    QString filePath = QFileDialog::getOpenFileName(this, "Import from CSV", QDir::homePath(), "CSV Files (*.csv)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open( /* flawfinder: ignore */ QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Error", "Could not open file for reading.");
        return;
    }

    struct csv_parser p;
    if (csv_init(&p, 0) != 0) {
        QMessageBox::critical(this, "Error", "Failed to initialize CSV parser.");
        return;
    }

    QStringList currentFields;
    char buf[4096]; // flawfinder: ignore // flawfinder: ignore
    qint64 bytes_read;
    while ((bytes_read = file.read( /* flawfinder: ignore */ buf, sizeof(buf))) > 0) {
        if (csv_parse(&p, buf, (size_t)bytes_read, import_field_cb, import_row_cb, &currentFields) != (size_t)bytes_read) {
            QMessageBox::critical(this, "CSV Parse Error", QString::fromStdString(csv_strerror(csv_error(&p))));
            break;
        }
    }

    csv_fini(&p, import_field_cb, import_row_cb, &currentFields);
    csv_free(&p);
    file.close();

    refreshEntryList();
    statusBar()->showMessage(QString("Import from %1 complete.").arg(filePath), 5000);
}


void MainWindow::onExport() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export to CSV", QDir::homePath() + "/export.csv", "CSV Files (*.csv)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open( /* flawfinder: ignore */ QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "service,username,password,totp_secret,recovery_codes\n";

    for (const auto& entry_meta : m_entries) {
        // Fetch full entry for export
        PasswordEntry *db_entry = database_get_entry_secure(entry_meta.id);
        if (db_entry) {
            // Suppress CodeQL warning: This is an intentional Export feature.
            // codeql[cpp/cleartext-storage-file]
            out << "\"" << sanitize_csv_field(QString::fromUtf8(db_entry->service)) << "\",";
            out << "\"" << sanitize_csv_field(QString::fromUtf8(db_entry->username)) << "\",";
            out << "\"" << sanitize_csv_field(QString::fromUtf8(db_entry->password)) << "\",";
            out << "\"" << sanitize_csv_field(QString::fromUtf8(db_entry->totp_secret)) << "\",";
            out << "\"" << sanitize_csv_field(QString::fromUtf8(db_entry->recovery_codes)) << "\"\n";
            free_password_entries(db_entry, 1);
        }
    }

    file.close();
    statusBar()->showMessage(QString("Exported %1 entries to %2").arg(m_entries.size()).arg(filePath), 5000);
}

void MainWindow::onSync() {
    SyncDialog dialog(this);
    dialog.exec();
}

void MainWindow::onSearchChanged(const QString &text) {
    if (text.isEmpty()) {
        refreshEntryList();
        return;
    }

    listWidget->clear();
    m_entries.clear();

    int count = 0;
    PasswordEntry *db_entries = database_search(text.toUtf8().constData(), &count);

    if (!db_entries) return;

    for (int i = 0; i < count; i++) {
        QListWidgetItem *item = new QListWidgetItem(QString::fromUtf8(db_entries[i].service));
        item->setData(Qt::UserRole, db_entries[i].id);
        listWidget->addItem(item);

        GUIPasswordEntry qt_entry;
        qt_entry.id = db_entries[i].id;
        qt_entry.service = QString::fromUtf8(db_entries[i].service);
        qt_entry.username = QString::fromUtf8(db_entries[i].username);
        m_entries.append(qt_entry);
    }

    free_password_entries(db_entries, count);
}

void MainWindow::refreshEntryList() {
    if (searchBar && !searchBar->text().isEmpty()) {
        onSearchChanged(searchBar->text());
        return;
    }
    listWidget->clear();
    m_entries.clear();

    int count = 0;
    PasswordEntry *db_entries = database_get_all_entries(&count);

    if (!db_entries) return;

    for (int i = 0; i < count; i++) {
        QListWidgetItem *item = new QListWidgetItem(QString::fromUtf8(db_entries[i].service));
        item->setData(Qt::UserRole, db_entries[i].id);
        listWidget->addItem(item);

        GUIPasswordEntry qt_entry;
        qt_entry.id = db_entries[i].id;
        qt_entry.service = QString::fromUtf8(db_entries[i].service);
        qt_entry.username = QString::fromUtf8(db_entries[i].username);
        m_entries.append(qt_entry);
    }

    free_password_entries(db_entries, count);
}

void MainWindow::onCurrentRowChanged(int currentRow) {
    totpTimer->stop();
    if (currentRow < 0 || currentRow >= m_entries.size()) {
        totpLabel->setText("------");
        totpProgressBar->setValue(0);
        recoveryCodesList->clear();
    } else {
        totpLabel->setText("------");
        totpProgressBar->setValue(0);
        recoveryCodesList->clear();

        // Fetch full entry for recovery codes display
        PasswordEntry *db_entry = database_get_entry_secure(m_entries[currentRow].id);
        if (db_entry) {
            QString codesStr = QString::fromUtf8(db_entry->recovery_codes);
            if (!codesStr.isEmpty()) {
                QStringList codes = codesStr.split("\n", Qt::SkipEmptyParts);
                for (const QString& code : codes) {
                    QListWidgetItem* item = new QListWidgetItem(code, recoveryCodesList);
                    if (code.startsWith("*")) {
                        QFont font = item->font();
                        font.setStrikeOut(true);
                        item->setFont(font);
                        item->setForeground(Qt::gray);
                    }
                }
            }
            free_password_entries(db_entry, 1);
        }

        updateTotpDisplay();
        totpTimer->start(1000);
    }
}

void MainWindow::updateTotpDisplay() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) return;

    // Fetch full entry for TOTP secret
    PasswordEntry *db_entry = database_get_entry_secure(m_entries[currentRow].id);
    if (!db_entry) return;

    const QString secret = QString::fromUtf8(db_entry->totp_secret);
    if (secret.isEmpty()) {
        totpLabel->setText("------");
        totpProgressBar->setValue(0);
        free_password_entries(db_entry, 1);
        return;
    }

    time_t now = time(NULL);
    int remaining = 30 - (int)(now % 30);
    totpProgressBar->setValue(remaining);

    if (remaining == 30 || totpLabel->text() == "------") {
        char *code = generate_totp_code(secret.toUtf8().constData());
        if (code) {
            totpLabel->setText(code);
            free(code);
        }
    }

    free_password_entries(db_entry, 1);
}

void MainWindow::onCopyTotp() {
    QString code = totpLabel->text();
    if (code == "------") {
        statusBar()->showMessage("No TOTP code to copy.", 3000);
        return;
    }
    QApplication::clipboard()->setText(code);
    statusBar()->showMessage("TOTP code copied to clipboard.", 3000);
}

void MainWindow::onAdd() {
    EntryDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        PasswordEntry entry;
        QByteArray service = dialog.getService().toUtf8();
        QByteArray username = dialog.getUsername().toUtf8();
        QByteArray password = dialog.getPassword().toUtf8();
        QByteArray totpSecret = dialog.getTotpSecret().toUtf8();
        QByteArray recoveryCodes = dialog.getRecoveryCodes().toUtf8();

        entry.service = (char*)service.constData();
        entry.username = (char*)username.constData();
        entry.password = (char*)password.constData();
        entry.totp_secret = (char*)totpSecret.constData();
        entry.recovery_codes = (char*)recoveryCodes.constData();

        if (database_add_entry(&entry) < 0) {
            QMessageBox::critical(this, "Database Error", "Failed to add new entry to the database.");
        } else {
            refreshEntryList();
        }
    }
}

void MainWindow::onEdit() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) {
        QMessageBox::warning(this, "No Selection", "Please select an entry to edit.");
        return;
    }

    QListWidgetItem *item = listWidget->item(currentRow);
    int entry_id = item->data(Qt::UserRole).toInt();

    // Fetch full entry for editing
    PasswordEntry *db_entry = database_get_entry_secure(entry_id);
    if (!db_entry) {
        QMessageBox::critical(this, "Error", "Failed to fetch entry details from database.");
        return;
    }

    EntryDialog dialog(this);
    dialog.setData(db_entry->id,
                   QString::fromUtf8(db_entry->service),
                   QString::fromUtf8(db_entry->username),
                   QString::fromUtf8(db_entry->password),
                   QString::fromUtf8(db_entry->totp_secret),
                   QString::fromUtf8(db_entry->recovery_codes));

    if (dialog.exec() == QDialog::Accepted) {
        PasswordEntry updated_entry;
        QByteArray service = dialog.getService().toUtf8();
        QByteArray username = dialog.getUsername().toUtf8();
        QByteArray password = dialog.getPassword().toUtf8();
        QByteArray totpSecret = dialog.getTotpSecret().toUtf8();
        QByteArray recoveryCodes = dialog.getRecoveryCodes().toUtf8();

        updated_entry.id = entry_id;
        updated_entry.service = (char*)service.constData();
        updated_entry.username = (char*)username.constData();
        updated_entry.password = (char*)password.constData();
        updated_entry.totp_secret = (char*)totpSecret.constData();
        updated_entry.recovery_codes = (char*)recoveryCodes.constData();

        if (database_update_entry(&updated_entry) != 0) {
            QMessageBox::critical(this, "Database Error", "Failed to update the entry in the database.");
        } else {
            refreshEntryList();
        }
    }

    free_password_entries(db_entry, 1);
}

void MainWindow::onCopyUsername() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) {
        statusBar()->showMessage("Please select an entry to copy from.", 3000);
        return;
    }
    QApplication::clipboard()->setText(m_entries[currentRow].username);
    statusBar()->showMessage("Username copied to clipboard.", 3000);
}

void MainWindow::onCopyPassword() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) {
        statusBar()->showMessage("Please select an entry to copy from.", 3000);
        return;
    }

    // Fetch full entry for password
    PasswordEntry *db_entry = database_get_entry_secure(m_entries[currentRow].id);
    if (!db_entry) {
        statusBar()->showMessage("Failed to fetch password from database.", 3000);
        return;
    }

    QString password = QString::fromUtf8(db_entry->password);
    QApplication::clipboard()->setText(password);

    statusBar()->showMessage("Password copied to clipboard. It will be cleared in 30 seconds.", 3000);
    QTimer::singleShot(30000, this, [password]() {
        if (QApplication::clipboard()->text() == password) {
            QApplication::clipboard()->clear();
        }
    });

    free_password_entries(db_entry, 1);
}

void MainWindow::setupUI() {
    setMinimumSize(800, 600);
    setWindowTitle("SecurePasswd_MGMT");

    // Central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Search Bar
    searchBar = new QLineEdit(this);
    searchBar->setPlaceholderText("Search services or usernames...");
    searchBar->setClearButtonEnabled(true);
    searchBar->addAction(QIcon(":/icons/search.svg"), QLineEdit::LeadingPosition);
    mainLayout->addWidget(searchBar);

    // Toolbar
    toolBar = new QToolBar(this);
    toolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    addToolBar(toolBar);

    // --- Group 1: Entry Management ---
    m_addAction = new QAction(QIcon(":/icons/add.svg"), "Add", this);
    m_addAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_A));
    m_addAction->setToolTip("Add new entry (Alt+A)");
    toolBar->addAction(m_addAction);

    editAction = new QAction(QIcon(":/icons/edit.svg"), "Edit", this);
    editAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_E));
    editAction->setToolTip("Edit selected entry (Alt+E)");
    toolBar->addAction(editAction);

    deleteAction = new QAction(QIcon(":/icons/delete.svg"), "Delete", this);
    deleteAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_D));
    deleteAction->setToolTip("Delete selected entry (Alt+D)");
    toolBar->addAction(deleteAction);

    toolBar->addSeparator();

    // --- Group 2: Copy Actions ---
    copyUsernameAction = new QAction(QIcon(":/icons/copy_username.svg"), "Copy Username", this);
    copyUsernameAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_U));
    copyUsernameAction->setToolTip("Copy username to clipboard (Alt+U)");
    toolBar->addAction(copyUsernameAction);

    copyPasswordAction = new QAction(QIcon(":/icons/copy_passwd.svg"), "Copy Password", this);
    copyPasswordAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_P));
    copyPasswordAction->setToolTip("Copy password to clipboard (Alt+P)");
    toolBar->addAction(copyPasswordAction);

    copyTotpAction = new QAction(QIcon(":/icons/copy_totp.svg"), "Copy TOTP", this);
    copyTotpAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_T));
    copyTotpAction->setToolTip("Copy TOTP code to clipboard (Alt+T)");
    toolBar->addAction(copyTotpAction);

    toolBar->addSeparator();

    // --- Group 3: Security Tools ---
    healthCheckAction = new QAction(QIcon(":/icons/health-check.svg"), "Health Check", this);
    healthCheckAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_H));
    healthCheckAction->setToolTip("Run password health check (Alt+H)");
    toolBar->addAction(healthCheckAction);

    changePasswordAction = new QAction(QIcon(":/icons/settings.svg"), "Change Master Password", this);
    changePasswordAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_S));
    changePasswordAction->setToolTip("Change Master Password (Alt+S)");
    toolBar->addAction(changePasswordAction);

    toolBar->addSeparator();

    // --- Group 4: Data Operations ---
    importAction = new QAction(QIcon(":/icons/import.svg"), "Import", this);
    importAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_I));
    importAction->setToolTip("Import from CSV (Alt+I)");
    toolBar->addAction(importAction);

    exportAction = new QAction(QIcon(":/icons/export.svg"), "Export", this);
    exportAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_X));
    exportAction->setToolTip("Export to CSV (Alt+X)");
    toolBar->addAction(exportAction);

    syncAction = new QAction(QIcon(":/icons/sync.svg"), "Sync to Mobile", this);
    syncAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_M));
    syncAction->setToolTip("Sync to Mobile (Alt+M)");
    toolBar->addAction(syncAction);

    toolBar->addSeparator();

    // --- Group 5: UI & Settings ---
    QAction *findAction = new QAction("Find", this);
    findAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_F));
    connect(findAction, &QAction::triggered, this, [this]() {
        searchBar->setFocus();
        searchBar->selectAll();
    });
    addAction(findAction);

    themeAction = new QAction(this);
    themeAction->setShortcut(QKeySequence(Qt::ALT | Qt::SHIFT | Qt::Key_T));
    toolBar->addAction(themeAction);

    toggleRecoveryCodesAction = new QAction(this);
    toggleRecoveryCodesAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_R));
    toolBar->addAction(toggleRecoveryCodesAction);
    updateRecoveryCodesIcon();

    toolBar->addSeparator();

    // --- Group 6: System ---
    QAction *exitAction = new QAction(QIcon(":/icons/exit.svg"), "Exit", this);
    exitAction->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Q));
    exitAction->setToolTip("Exit Application (Alt+Q)");
    toolBar->addAction(exitAction);
    connect(exitAction, &QAction::triggered, qApp, &QApplication::quit);


    // List widget
    listWidget = new QListWidget(this);
    mainLayout->addWidget(listWidget);

    // TOTP display
    QHBoxLayout *totpLayout = new QHBoxLayout();
    totpLabel = new QLabel("------", this);
    totpProgressBar = new QProgressBar(this);
    totpProgressBar->setRange(0, 30);
    totpLayout->addWidget(new QLabel("TOTP:", this));
    totpLayout->addWidget(totpLabel);
    totpLayout->addWidget(totpProgressBar);
    mainLayout->addLayout(totpLayout);

    // Recovery codes display
    recoveryCodesLabel = new QLabel("2FA Recovery Codes:", this);
    mainLayout->addWidget(recoveryCodesLabel);

    QHBoxLayout *recoveryLayout = new QHBoxLayout();
    recoveryCodesList = new QListWidget(this);
    recoveryCodesList->setMaximumHeight(100);
    recoveryLayout->addWidget(recoveryCodesList);

    markUsedButton = new QPushButton("Mark as Used", this);
    recoveryLayout->addWidget(markUsedButton);
    mainLayout->addLayout(recoveryLayout);

    updateRecoveryCodesVisibility();

    // Status bar
    statusBar();

    // Connections
    connect(m_addAction, &QAction::triggered, this, &MainWindow::onAdd);
    connect(editAction, &QAction::triggered, this, &MainWindow::onEdit);
    connect(deleteAction, &QAction::triggered, this, &MainWindow::onDelete);
    connect(copyUsernameAction, &QAction::triggered, this, &MainWindow::onCopyUsername);
    connect(copyPasswordAction, &QAction::triggered, this, &MainWindow::onCopyPassword);
    connect(copyTotpAction, &QAction::triggered, this, &MainWindow::onCopyTotp);
    connect(importAction, &QAction::triggered, this, &MainWindow::onImport);
    connect(exportAction, &QAction::triggered, this, &MainWindow::onExport);
    connect(syncAction, &QAction::triggered, this, &MainWindow::onSync);
    connect(healthCheckAction, &QAction::triggered, this, &MainWindow::onHealthCheck);
    connect(changePasswordAction, &QAction::triggered, this, &MainWindow::onChangePassword);
    connect(listWidget, &QListWidget::currentRowChanged, this, &MainWindow::onCurrentRowChanged);
    connect(themeAction, &QAction::triggered, this, &MainWindow::onToggleTheme);
    connect(toggleRecoveryCodesAction, &QAction::triggered, this, &MainWindow::onToggleRecoveryCodes);
    connect(markUsedButton, &QPushButton::clicked, this, &MainWindow::onMarkAsUsed);
    connect(searchBar, &QLineEdit::textChanged, this, &MainWindow::onSearchChanged);

    // TOTP timer
    totpTimer = new QTimer(this);
    connect(totpTimer, &QTimer::timeout, this, &MainWindow::updateTotpDisplay);

    // Security: Clear clipboard on exit
    connect(qApp, &QApplication::aboutToQuit, this, []() {
        QApplication::clipboard()->clear();
    });
}

void MainWindow::onHealthCheck() {
    HealthCheckDialog dialog(m_entries, this);
    dialog.exec();
}

void MainWindow::onDelete() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) {
        QMessageBox::warning(this, "No Selection", "Please select an entry to delete.");
        return;
    }

    QListWidgetItem *item = listWidget->item(currentRow);
    int entry_id = item->data(Qt::UserRole).toInt();

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Confirm Delete", "Are you sure you want to delete this entry?",
                                  QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::No) {
        return;
    }

    if (database_delete_entry(entry_id) != 0) {
        QMessageBox::critical(this, "Database Error", "Failed to delete entry from the database.");
    } else {
        refreshEntryList();
        statusBar()->showMessage("Entry deleted successfully.", 3000);
    }
}

void MainWindow::onToggleTheme() {
    if (currentTheme == "light") {
        currentTheme = "dark";
    } else {
        currentTheme = "light";
    }
    QSettings settings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    settings.setValue("theme", currentTheme);
    loadTheme(currentTheme);
}

void MainWindow::loadTheme(const QString& theme) {
    QFile file(QString(":/%1.qss").arg(theme));
    if (file.open( /* flawfinder: ignore */ QFile::ReadOnly | QFile::Text)) {
        qApp->setStyleSheet(file.readAll());
        file.close();
    }
    updateThemeIcon();
}

void MainWindow::onChangePassword() {
    bool ok;
    QString newPass = QInputDialog::getText(this, "Change Master Password",
                                            "Enter new master password:", QLineEdit::Password,
                                            "", &ok);
    if (!ok || newPass.isEmpty()) return;

    QString confirmPass = QInputDialog::getText(this, "Change Master Password",
                                                "Confirm new master password:", QLineEdit::Password,
                                                "", &ok);
    if (!ok) return;

    if (newPass != confirmPass) {
        QMessageBox::warning(this, "Error", "Passwords do not match.");
        return;
    }

    if (database_rekey(newPass.toUtf8().constData()) == 0) {
        QMessageBox::information(this, "Success", "Master password changed successfully.");
    } else {
        QMessageBox::critical(this, "Error", "Failed to change master password.");
    }
}

void MainWindow::onToggleRecoveryCodes() {
    recoveryCodesEnabled = !recoveryCodesEnabled;
    QSettings settings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    settings.setValue("recovery_codes_enabled", recoveryCodesEnabled);
    updateRecoveryCodesVisibility();
    updateRecoveryCodesIcon();
}

void MainWindow::updateRecoveryCodesIcon() {
    if (recoveryCodesEnabled) {
        toggleRecoveryCodesAction->setIcon(QIcon(":/icons/recovery-enabled.svg"));
        toggleRecoveryCodesAction->setText("Disable Recovery Codes");
    } else {
        toggleRecoveryCodesAction->setIcon(QIcon(":/icons/recovery-disabled.svg"));
        toggleRecoveryCodesAction->setText("Enable Recovery Codes");
    }
}

void MainWindow::updateRecoveryCodesVisibility() {
    if (recoveryCodesLabel) recoveryCodesLabel->setVisible(recoveryCodesEnabled);
    if (recoveryCodesList) recoveryCodesList->setVisible(recoveryCodesEnabled);
    if (markUsedButton) markUsedButton->setVisible(recoveryCodesEnabled);
}

void MainWindow::onMarkAsUsed() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) return;

    QListWidgetItem *selectedItem = recoveryCodesList->currentItem();
    if (!selectedItem) {
        QMessageBox::warning(this, "No Selection", "Please select a recovery code to mark as used.");
        return;
    }

    QString code = selectedItem->text();
    if (code.startsWith("*")) {
        return; // Already used
    }

    // Fetch full entry to update recovery codes
    PasswordEntry *db_entry = database_get_entry_secure(m_entries[currentRow].id);
    if (!db_entry) return;

    QString originalCodes = QString::fromUtf8(db_entry->recovery_codes);
    QStringList codesList = originalCodes.split("\n", Qt::SkipEmptyParts);
    for (int i = 0; i < codesList.size(); ++i) {
        if (codesList[i] == code) {
            codesList[i] = "*" + code;
            break;
        }
    }
    QString newCodes = codesList.join("\n");

    // Update database
    PasswordEntry updated_entry;
    updated_entry.id = db_entry->id;
    QByteArray service = QString::fromUtf8(db_entry->service).toUtf8();
    QByteArray username = QString::fromUtf8(db_entry->username).toUtf8();
    QByteArray password = QString::fromUtf8(db_entry->password).toUtf8();
    QByteArray totpSecret = QString::fromUtf8(db_entry->totp_secret).toUtf8();
    QByteArray recoveryCodesByte = newCodes.toUtf8();

    updated_entry.service = (char*)service.constData();
    updated_entry.username = (char*)username.constData();
    updated_entry.password = (char*)password.constData();
    updated_entry.totp_secret = (char*)totpSecret.constData();
    updated_entry.recovery_codes = (char*)recoveryCodesByte.constData();

    if (database_update_entry(&updated_entry) != 0) {
        QMessageBox::critical(this, "Database Error", "Failed to update the entry in the database.");
    } else {
        // Update list item visual
        QFont font = selectedItem->font();
        font.setStrikeOut(true);
        selectedItem->setFont(font);
        selectedItem->setText("*" + code);
        selectedItem->setForeground(Qt::gray);
        statusBar()->showMessage("Recovery code marked as used.", 3000);
    }

    free_password_entries(db_entry, 1);
}

void MainWindow::updateThemeIcon() {
    if (currentTheme == "light") {
        themeAction->setIcon(QIcon(":/icons/darkmode.svg"));
        themeAction->setText("Dark Theme");
    } else {
        themeAction->setIcon(QIcon(":/icons/lightmode.svg"));
        themeAction->setText("Light Theme");
    }
}
