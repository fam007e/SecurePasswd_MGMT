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
class QToolBar;
class QAction;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(const QString& password, QWidget *parent = nullptr);
    ~MainWindow();

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
    void onHealthCheck();
    void onToggleTheme();

private:
    void setupUI();
    void refreshEntryList();
    void loadTheme(const QString& theme);
    void updateThemeIcon();


    QListWidget *listWidget;
    QVector<GUIPasswordEntry> m_entries; // UI Cache
    QToolBar *toolBar;
    QMenu *fileMenu;
    QMenu *toolsMenu;
    QAction *addAction;
    QAction *editAction;
    QAction *copyUsernameAction;
    QAction *copyPasswordAction;
    QAction *copyTotpAction;
    QAction *importAction;
    QAction *exportAction;
    QAction *healthCheckAction;
    QAction *themeAction;
    QString currentTheme;
    QVector<GUIPasswordEntry> entries;

    // TOTP Display
    QLabel *totpLabel;
    QProgressBar *totpProgressBar;
    QTimer *totpTimer;
};

#endif // MAINWINDOW_H