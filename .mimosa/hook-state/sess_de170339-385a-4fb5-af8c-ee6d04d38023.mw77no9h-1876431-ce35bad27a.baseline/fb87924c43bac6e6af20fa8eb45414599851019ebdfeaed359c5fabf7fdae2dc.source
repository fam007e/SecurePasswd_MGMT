#ifndef GPGKEYSDIALOG_H
#define GPGKEYSDIALOG_H

#include <QDialog>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>

/**
 * @class GpgKeysDialog
 * @brief Manages the OpenPGP key store inside the vault.
 *
 * Lists stored armored keys, supports importing (paste), editing,
 * deleting and copying the public key to the clipboard. Keys are stored
 * encrypted inside the SQLCipher vault and participate in 2-way sync
 * with the same newer-wins/tombstone rules as password entries.
 */
class GpgKeysDialog : public QDialog {
    Q_OBJECT

public:
    explicit GpgKeysDialog(QWidget *parent = nullptr);

private slots:
    void onAddOrSave();
    void onDelete();
    void onCopyPublicKey();
    void onSelectionChanged();

private:
    void reload();
    int selectedId() const;

    QListWidget *keyList;
    QLineEdit *labelEdit;
    QLineEdit *emailEdit;
    QLineEdit *keyIdEdit;
    QPlainTextEdit *keyEdit;
    QLabel *statusLabel;
    QPushButton *saveButton;
    QPushButton *deleteButton;
    QPushButton *copyButton;
    int editingId = 0; /* 0 = adding a new key */
};

#endif // GPGKEYSDIALOG_H
