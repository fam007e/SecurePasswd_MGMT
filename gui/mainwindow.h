#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <cstdint>
#include <QVector>
#include "passwordentry.h"

#include <QLabel>
#include <QProgressBar>
#include <QTimer>

#include <QMenu>

class QListWidget;
class QTextEdit;
class QToolBar;
class QAction;
class QPushButton;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(const QString& password, QWidget *parent = nullptr);
    ~MainWindow();

    bool isDatabaseOpen() const { return m_databaseOpen; }

private slots:
    void onAdd();
    void onEdit();
    void onCopyUsername();
    void onCopyPassword();
    void onCopyTotp();
    void onCurrentRowChanged(int currentRow);
    void updateTotpDisplay();
    void onImport();
    void onExport();
    void onDelete();
    void onHealthCheck();
    void onToggleTheme();
    void onToggleRecoveryCodes();
    void onMarkAsUsed();

private:
    void setupUI();
    void refreshEntryList();
    void loadTheme(const QString& theme);
    void updateThemeIcon();
    void updateRecoveryCodesIcon();
    void updateRecoveryCodesVisibility();


    QListWidget *listWidget;
    QVector<GUIPasswordEntry> m_entries; // UI Cache
    QToolBar *toolBar;
    QAction *addAction;
    QAction *editAction;
    QAction *copyUsernameAction;
    QAction *copyPasswordAction;
    QAction *copyTotpAction;
    QAction *deleteAction;
    QAction *importAction;
    QAction *exportAction;
    QAction *healthCheckAction;
    QAction *themeAction;
    QAction *toggleRecoveryCodesAction;
    QString currentTheme;

    // TOTP Display
    QLabel *totpLabel;
    QProgressBar *totpProgressBar;
    QTimer *totpTimer;

    // Recovery Codes Display
    QLabel *recoveryCodesLabel;
    QListWidget *recoveryCodesList;
    QPushButton *markUsedButton;
    bool recoveryCodesEnabled;

    bool m_databaseOpen;
};

#endif // MAINWINDOW_H
