#include "mainwindow.h"
#include "entrydialog.h"
#include "healthcheckdialog.h"
#include <csv.h>

extern "C" {
#include "database.h"
#include "totp.h"
#include "platform_paths.h"
}

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDataStream>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QIcon>
#include <QHBoxLayout>
#include <QListWidget>
#include <QMenuBar>
#include <QSettings>
#include <QStyleFactory>
#include <QMessageBox>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>
#include <cstring>
#include <sodium.h>
#include <time.h>

// Callbacks for libcsv import
void import_field_cb(void *s, size_t len, void *data) {
    static_cast<QStringList*>(data)->append(QString::fromUtf8((char*)s, len));
}
void import_row_cb(int c, void *data) {
    QStringList *fields = static_cast<QStringList*>(data);
    if (fields->size() >= 3) { // service,username,password are required
        PasswordEntry entry;
        QByteArray service = fields->at(0).toUtf8();
        QByteArray username = fields->at(1).toUtf8();
        QByteArray password = fields->at(2).toUtf8();
        QByteArray totpSecret = (fields->size() >= 4) ? fields->at(3).toUtf8() : QByteArray();
        QByteArray recoveryCodes = (fields->size() >= 5) ? fields->at(4).toUtf8() : QByteArray();

        entry.service = (char*)service.constData();
        entry.username = (char*)username.constData();
        entry.password = (char*)password.constData();
        entry.totp_secret = (char*)totpSecret.constData();
        entry.recovery_codes = (char*)recoveryCodes.constData();

        database_add_entry(&entry);
    }
    fields->clear();
}

MainWindow::MainWindow(const QString& password, QWidget *parent) : QMainWindow(parent), m_databaseOpen(false) {
    // Use shared platform_paths function
    char dirPath[2048]; // flawfinder: ignore
    get_config_path(dirPath, sizeof(dirPath));
    QString dbDirPath = QString::fromUtf8(dirPath);

    QDir dir(dbDirPath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    QString dbPath = dbDirPath + "/vault.db";

    if (database_open(dbPath.toUtf8().constData(), password.toUtf8().constData()) != 0) {
        QMessageBox::critical(nullptr, "Database Error", "Failed to open database. Check master password or file permissions.\n\nThe application will now exit.");
        QTimer::singleShot(0, qApp, &QApplication::quit);
        return;
    }

    m_databaseOpen = true;
    setupUI();
    refreshEntryList();

    QSettings settings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    currentTheme = settings.value("theme", "light").toString();
    loadTheme(currentTheme);

    recoveryCodesEnabled = settings.value("recovery_codes_enabled", false).toBool();
    updateRecoveryCodesVisibility();
}

MainWindow::~MainWindow() {
    database_close();
}

void MainWindow::onImport() {
    QString filePath = QFileDialog::getOpenFileName(this, "Import from CSV", QDir::homePath(), "CSV Files (*.csv)");
    if (filePath.isEmpty()) return;

    FILE *fp = fopen(filePath.toUtf8().constData(), "rb"); // flawfinder: ignore
    if (!fp) {
        QMessageBox::critical(this, "Error", "Could not open file for reading.");
        return;
    }

    struct csv_parser p;
    if (csv_init(&p, 0) != 0) {
        QMessageBox::critical(this, "Error", "Failed to initialize CSV parser.");
        fclose(fp);
        return;
    }

    QStringList currentFields;

    char buf[1024]; // flawfinder: ignore
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0) { // flawfinder: ignore
        if (csv_parse(&p, buf, bytes_read, import_field_cb, import_row_cb, &currentFields) != bytes_read) {
            QMessageBox::critical(this, "CSV Parse Error", QString::fromStdString(csv_strerror(csv_error(&p))));
            break;
        }
    }

    csv_fini(&p, import_field_cb, import_row_cb, &currentFields); // Finalize parsing
    csv_free(&p);
    fclose(fp);

    refreshEntryList();
    statusBar()->showMessage(QString("Import from %1 complete.").arg(filePath), 5000);
}

void MainWindow::onExport() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export to CSV", QDir::homePath() + "/export.csv", "CSV Files (*.csv)");
    if (filePath.isEmpty()) return;

    FILE *fp = fopen(filePath.toUtf8().constData(), "wb"); // flawfinder: ignore
    if (!fp) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    fputs("service,username,password,totp_secret,recovery_codes\n", fp);
    for (const auto& entry : m_entries) {
        fprintf(fp, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", // flawfinder: ignore
                entry.service.toUtf8().constData(),
                entry.username.toUtf8().constData(),
                entry.password.toUtf8().constData(),
                entry.totpSecret.toUtf8().constData(),
                entry.recoveryCodes.toUtf8().constData());
    }

    fclose(fp);
    statusBar()->showMessage(QString("Exported %1 entries to %2").arg(m_entries.size()).arg(filePath), 5000);
}

void MainWindow::refreshEntryList() {
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
        qt_entry.password = QString::fromUtf8(db_entries[i].password);
        qt_entry.totpSecret = QString::fromUtf8(db_entries[i].totp_secret);
        qt_entry.recoveryCodes = QString::fromUtf8(db_entries[i].recovery_codes);
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
        QString codesStr = m_entries[currentRow].recoveryCodes;
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
        updateTotpDisplay();
        totpTimer->start(1000);
    }
}

void MainWindow::updateTotpDisplay() {
    int currentRow = listWidget->currentRow();
    if (currentRow < 0 || currentRow >= m_entries.size()) return;

    const QString secret = m_entries[currentRow].totpSecret;
    if (secret.isEmpty()) {
        totpLabel->setText("------");
        totpProgressBar->setValue(0);
        return;
    }

    time_t now = time(NULL);
    int remaining = 30 - (now % 30);
    totpProgressBar->setValue(remaining);

    if (remaining == 30 || totpLabel->text() == "------") {
        char *code = generate_totp_code(secret.toUtf8().constData());
        if (code) {
            totpLabel->setText(code);
            free(code);
        }
    }
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

    EntryDialog dialog(this);
    dialog.setData(m_entries[currentRow]); // Use the cache to populate dialog

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
    QString password = m_entries[currentRow].password;
    QApplication::clipboard()->setText(password);
    statusBar()->showMessage("Password copied to clipboard. It will be cleared in 30 seconds.", 3000);
    QTimer::singleShot(30000, this, [password]() {
        if (QApplication::clipboard()->text() == password) {
            QApplication::clipboard()->clear();
        }
    });
}

void MainWindow::setupUI() {
    setMinimumSize(800, 600);
    setWindowTitle("SecurePasswd_MGMT");

    // Central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Toolbar
    toolBar = new QToolBar(this);
    toolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    addToolBar(toolBar);

    // Menus (Removed for icon-only UI)

    addAction = new QAction(QIcon(":/icons/add.svg"), "Add", this);
    toolBar->addAction(addAction);

    editAction = new QAction(QIcon(":/icons/edit.svg"), "Edit", this);
    toolBar->addAction(editAction);

    deleteAction = new QAction(QIcon(":/icons/delete.svg"), "Delete", this);
    toolBar->addAction(deleteAction);

    copyUsernameAction = new QAction(QIcon(":/icons/copy_username.svg"), "Copy Username", this);
    toolBar->addAction(copyUsernameAction);

    copyPasswordAction = new QAction(QIcon(":/icons/copy_passwd.svg"), "Copy Password", this);
    toolBar->addAction(copyPasswordAction);

    copyTotpAction = new QAction(QIcon(":/icons/copy_totp.svg"), "Copy TOTP", this);
    toolBar->addAction(copyTotpAction);

    toolBar->addSeparator();

    healthCheckAction = new QAction(QIcon(":/icons/health-check.svg"), "Health Check", this);
    toolBar->addAction(healthCheckAction);

    toolBar->addSeparator();

    importAction = new QAction(QIcon(":/icons/import.svg"), "Import", this);
    toolBar->addAction(importAction);

    exportAction = new QAction(QIcon(":/icons/export.svg"), "Export", this);
    toolBar->addAction(exportAction);

    toolBar->addSeparator();

    themeAction = new QAction(this);
    toolBar->addAction(themeAction);

    toggleRecoveryCodesAction = new QAction(this);
    toolBar->addAction(toggleRecoveryCodesAction);
    updateRecoveryCodesIcon();

    toolBar->addSeparator();

    QAction *exitAction = new QAction(QIcon(":/icons/exit.svg"), "Exit", this);
    exitAction->setToolTip("Exit Application");
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
    connect(addAction, &QAction::triggered, this, &MainWindow::onAdd);
    connect(editAction, &QAction::triggered, this, &MainWindow::onEdit);
    connect(deleteAction, &QAction::triggered, this, &MainWindow::onDelete);
    connect(copyUsernameAction, &QAction::triggered, this, &MainWindow::onCopyUsername);
    connect(copyPasswordAction, &QAction::triggered, this, &MainWindow::onCopyPassword);
    connect(copyTotpAction, &QAction::triggered, this, &MainWindow::onCopyTotp);
    connect(importAction, &QAction::triggered, this, &MainWindow::onImport);
    connect(exportAction, &QAction::triggered, this, &MainWindow::onExport);
    connect(healthCheckAction, &QAction::triggered, this, &MainWindow::onHealthCheck);
    connect(listWidget, &QListWidget::currentRowChanged, this, &MainWindow::onCurrentRowChanged);
    connect(themeAction, &QAction::triggered, this, &MainWindow::onToggleTheme);
    connect(toggleRecoveryCodesAction, &QAction::triggered, this, &MainWindow::onToggleRecoveryCodes);
    connect(markUsedButton, &QPushButton::clicked, this, &MainWindow::onMarkAsUsed);

    // TOTP timer
    totpTimer = new QTimer(this);
    connect(totpTimer, &QTimer::timeout, this, &MainWindow::updateTotpDisplay);
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
    if (file.open(QFile::ReadOnly | QFile::Text)) { // flawfinder: ignore
        qApp->setStyleSheet(file.readAll());
        file.close();
    }
    updateThemeIcon();
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

    // Mark as used in UI Cache
    QString originalCodes = m_entries[currentRow].recoveryCodes;
    QStringList codesList = originalCodes.split("\n", Qt::SkipEmptyParts);
    for (int i = 0; i < codesList.size(); ++i) {
        if (codesList[i] == code) {
            codesList[i] = "*" + code;
            break;
        }
    }
    m_entries[currentRow].recoveryCodes = codesList.join("\n");

    // Update database
    PasswordEntry updated_entry;
    updated_entry.id = m_entries[currentRow].id;
    QByteArray service = m_entries[currentRow].service.toUtf8();
    QByteArray username = m_entries[currentRow].username.toUtf8();
    QByteArray password = m_entries[currentRow].password.toUtf8();
    QByteArray totpSecret = m_entries[currentRow].totpSecret.toUtf8();
    QByteArray recoveryCodes = m_entries[currentRow].recoveryCodes.toUtf8();

    updated_entry.service = (char*)service.constData();
    updated_entry.username = (char*)username.constData();
    updated_entry.password = (char*)password.constData();
    updated_entry.totp_secret = (char*)totpSecret.constData();
    updated_entry.recovery_codes = (char*)recoveryCodes.constData();

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
