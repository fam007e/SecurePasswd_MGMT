#include "gpgkeysdialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGuiApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QShortcut>

extern "C" {
#include "database.h"
}

GpgKeysDialog::GpgKeysDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("OpenPGP Keys");
    setMinimumSize(560, 520);

    QVBoxLayout *layout = new QVBoxLayout(this);

    keyList = new QListWidget(this);
    keyList->setMinimumHeight(140);
    layout->addWidget(new QLabel("Stored keys:", this));
    layout->addWidget(keyList);

    QFormLayout *form = new QFormLayout;
    labelEdit = new QLineEdit(this);
    emailEdit = new QLineEdit(this);
    keyIdEdit = new QLineEdit(this);
    form->addRow("Label:", labelEdit);
    form->addRow("Email:", emailEdit);
    form->addRow("Key ID:", keyIdEdit);
    layout->addLayout(form);

    layout->addWidget(new QLabel("Armored key (paste public and/or secret key block):", this));
    keyEdit = new QPlainTextEdit(this);
    keyEdit->setMinimumHeight(140);
    keyEdit->setPlaceholderText("-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----");
    layout->addWidget(keyEdit);

    statusLabel = new QLabel(this);
    layout->addWidget(statusLabel);

    QHBoxLayout *buttons = new QHBoxLayout;
    saveButton = new QPushButton("&Save Key", this);
    saveButton->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_S));
    saveButton->setToolTip("Save or update key (Ctrl+S)");

    QPushButton *clearButton = new QPushButton("&New", this);
    clearButton->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_N));
    clearButton->setToolTip("Create new key / clear form (Ctrl+N)");

    deleteButton = new QPushButton("&Delete", this);
    deleteButton->setToolTip("Delete selected key (Delete or Alt+D)");

    copyButton = new QPushButton("&Copy Public Key", this);
    copyButton->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
    copyButton->setToolTip("Copy public key to clipboard (Ctrl+Shift+C)");

    QPushButton *closeButton = new QPushButton("Close", this);
    buttons->addWidget(saveButton);
    buttons->addWidget(clearButton);
    buttons->addWidget(copyButton);
    buttons->addWidget(deleteButton);
    buttons->addStretch(1);
    buttons->addWidget(closeButton);
    layout->addLayout(buttons);

    // Delete key shortcut when keyList is focused
    QShortcut *keyListDeleteShortcut = new QShortcut(QKeySequence::Delete, keyList);
    keyListDeleteShortcut->setContext(Qt::WidgetShortcut);
    connect(keyListDeleteShortcut, &QShortcut::activated, this, &GpgKeysDialog::onDelete);

    connect(keyList, &QListWidget::itemSelectionChanged,
            this, &GpgKeysDialog::onSelectionChanged);
    connect(saveButton, &QPushButton::clicked, this, &GpgKeysDialog::onAddOrSave);
    connect(deleteButton, &QPushButton::clicked, this, &GpgKeysDialog::onDelete);
    connect(copyButton, &QPushButton::clicked, this, &GpgKeysDialog::onCopyPublicKey);
    connect(clearButton, &QPushButton::clicked, this, [this]() {
        editingId = 0;
        labelEdit->clear(); emailEdit->clear(); keyIdEdit->clear(); keyEdit->clear();
        keyList->clearSelection();
        saveButton->setText("&Save Key");
    });
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);

    reload();
}

void GpgKeysDialog::reload() {
    keyList->clear();
    int count = 0;
    GpgKey *keys = database_gpg_get_all(&count);
    for (int i = 0; i < count; i++) {
        QString item = QString("%1  (%2)%3")
                           .arg(keys[i].label)
                           .arg(keys[i].email && keys[i].email[0] ? keys[i].email : "no email")
                           .arg(keys[i].private_key && keys[i].private_key[0]
                                    ? "  [secret present]" : "");
        QListWidgetItem *row = new QListWidgetItem(item, keyList);
        row->setData(Qt::UserRole, keys[i].id);
    }
    database_gpg_free(keys, count);
    if (count == 0) {
        statusLabel->setText("No OpenPGP keys stored yet. Paste an armored key below and press Save Key.");
    } else {
        statusLabel->clear();
    }
}

int GpgKeysDialog::selectedId() const {
    QListWidgetItem *item = keyList->currentItem();
    return item ? item->data(Qt::UserRole).toInt() : 0;
}

void GpgKeysDialog::onSelectionChanged() {
    int id = selectedId();
    if (id <= 0) return;

    int count = 0;
    GpgKey *keys = database_gpg_get_all(&count);
    for (int i = 0; i < count; i++) {
        if (keys[i].id == id) {
            editingId = id;
            labelEdit->setText(keys[i].label);
            emailEdit->setText(keys[i].email);
            keyIdEdit->setText(keys[i].key_id);
            // Prefer showing the public key; the secret key is present in
            // the vault but editing it by mistake is more dangerous than
            // useful in this simple editor.
            keyEdit->setPlainText(
                keys[i].public_key && keys[i].public_key[0]
                    ? keys[i].public_key : keys[i].private_key);
            saveButton->setText("&Update Key");
            break;
        }
    }
    database_gpg_free(keys, count);
}

void GpgKeysDialog::onAddOrSave() {
    GpgKey key;
    memset(&key, 0, sizeof(key));
    key.id = editingId;
    key.label = labelEdit->text().toUtf8().data();
    key.email = emailEdit->text().toUtf8().data();
    key.key_id = keyIdEdit->text().toUtf8().data();
    QByteArray armor = keyEdit->toPlainText().toUtf8();
    // Route the block to public or secret storage by its armor header;
    // a paste containing both blocks keeps the whole text in public_key
    // for simplicity (it round-trips through sync verbatim).
    if (armor.contains("BEGIN PGP PRIVATE KEY BLOCK")) {
        key.private_key = armor.data();
    } else {
        key.public_key = armor.data();
    }

    int rc = editingId > 0 ? database_gpg_update(&key) : database_gpg_add(&key);
    if (rc < 0) {
        QMessageBox::warning(this, "Error", "Could not store the key. Is the label unique?");
        return;
    }
    editingId = 0;
    saveButton->setText("&Save Key");
    labelEdit->clear(); emailEdit->clear(); keyIdEdit->clear(); keyEdit->clear();
    reload();
    statusLabel->setText("Key stored (encrypted with the vault).");
}

void GpgKeysDialog::onDelete() {
    int id = selectedId();
    if (id <= 0) {
        QMessageBox::information(this, "Delete", "Select a key first.");
        return;
    }
    if (QMessageBox::question(this, "Confirm Delete",
                              "Delete this OpenPGP key from the vault?\n"
                              "The deletion will propagate on the next sync.") != QMessageBox::Yes) {
        return;
    }
    if (database_gpg_delete(id) != 0) {
        QMessageBox::warning(this, "Error", "Failed to delete the key.");
        return;
    }
    editingId = 0;
    saveButton->setText("&Save Key");
    labelEdit->clear(); emailEdit->clear(); keyIdEdit->clear(); keyEdit->clear();
    reload();
}

void GpgKeysDialog::onCopyPublicKey() {
    int id = selectedId();
    if (id <= 0) return;
    int count = 0;
    GpgKey *keys = database_gpg_get_all(&count);
    for (int i = 0; i < count; i++) {
        if (keys[i].id == id && keys[i].public_key && keys[i].public_key[0]) {
            QGuiApplication::clipboard()->setText(QString::fromUtf8(keys[i].public_key));
            statusLabel->setText("Public key copied to clipboard.");
            break;
        }
    }
    database_gpg_free(keys, count);
}
