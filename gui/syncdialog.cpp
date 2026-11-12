#include "syncdialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QSpinBox>
#include <QSettings>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QTcpSocket>
#include <QPainter>
#include <QImage>
#include <QPixmap>
#include <QHostAddress>
#include <QFile>
#include <QGuiApplication>
#include <QClipboard>
#include <QTimer>
#include <QStyle>
#include <vector>
#include <algorithm>
#include "qrcodegen/qrcodegen.hpp"

extern "C" {
#include "database.h"
#include "platform_paths.h"
#include <openssl/rand.h>
}

static QByteArray pskToBase64Url(const QByteArray &raw) {
    return raw.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

SyncDialog::SyncDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Vault Sync");
    setMinimumSize(460, 620);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(10);
    layout->setContentsMargins(20, 20, 20, 20);

    qrLabel = new QLabel(this);
    qrLabel->setAlignment(Qt::AlignCenter);
    qrLabel->setMinimumSize(280, 280);
    layout->addWidget(qrLabel);

    QHBoxLayout *ipLayout = new QHBoxLayout();
    QLabel *ipPromptLabel = new QLabel("Network Interface:", this);
    ipComboBox = new QComboBox(this);
    ipLayout->addWidget(ipPromptLabel);
    ipLayout->addWidget(ipComboBox, 1);
    layout->addLayout(ipLayout);

    QHBoxLayout *portLayout = new QHBoxLayout();
    QLabel *portPromptLabel = new QLabel("Port:", this);
    portSpinBox = new QSpinBox(this);
    portSpinBox->setRange(1, 65535);
    portSpinBox->setValue((int)serverPort);
    portSpinBox->setToolTip("Preferred TCP port for Vault Sync. Remembered for future sessions; a random port is used automatically when this one is busy.");
    portLayout->addWidget(portPromptLabel);
    portLayout->addWidget(portSpinBox);
    portLayout->addStretch(1);
    layout->addLayout(portLayout);
    connect(portSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SyncDialog::onPortChanged);

    // Status card: mirrors the mobile app's status surface (DESIGN_TOKENS.md).
    QFrame *statusCard = new QFrame(this);
    statusCard->setObjectName("statusCard");
    QVBoxLayout *statusLayout = new QVBoxLayout(statusCard);
    statusLabel = new QLabel("Waiting for the mobile app… Scan the QR code.", statusCard);
    statusLabel->setAlignment(Qt::AlignCenter);
    statusLabel->setWordWrap(true);
    statusLayout->addWidget(statusLabel);
    layout->addWidget(statusCard);

    // Summary card: per-change results; border turns green on success,
    // red on failure (variant property, styled in the theme files).
    summaryCard = new QFrame(this);
    summaryCard->setObjectName("summaryCard");
    QVBoxLayout *summaryLayout = new QVBoxLayout(summaryCard);
    detailBox = new QPlainTextEdit(summaryCard);
    detailBox->setReadOnly(true);
    detailBox->setMaximumHeight(140);
    detailBox->hide();
    summaryLayout->addWidget(detailBox);
    summaryCard->hide();
    layout->addWidget(summaryCard);

    QHBoxLayout *btnLayout = new QHBoxLayout();
    copyButton = new QPushButton(QIcon(":/icons/copy_passwd.svg"), "&Copy Sync Code", this);
    copyButton->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_C));
    copyButton->setToolTip("Copy Sync Code (Ctrl+C)");
    closeButton = new QPushButton(QIcon(":/icons/exit.svg"), "Close", this);
    btnLayout->addWidget(copyButton);
    btnLayout->addWidget(closeButton);
    layout->addLayout(btnLayout);

    connect(copyButton, &QPushButton::clicked, this, &SyncDialog::onCopySyncCodeClicked);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);

    // Fresh 512-bit pairing secret for this session only (never persisted).
    pairingSecret.resize(SYNC_PSK_LEN);
    RAND_bytes(reinterpret_cast<unsigned char *>(pairingSecret.data()), SYNC_PSK_LEN);

    // Start TCP Server on the user's preferred port (default 33261) to
    // help with firewall configuration; falls back to a random port when
    // the preferred one is busy.
    tcpServer = new QTcpServer(this);
    QSettings syncSettings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    serverPort = (quint16)syncSettings.value("sync_port", 33261).toUInt();
    if (serverPort == 0) serverPort = 33261;
    if (!tcpServer->listen(QHostAddress::AnyIPv4, serverPort)) {
        // Fallback to random port if fixed port is busy
        if (!tcpServer->listen(QHostAddress::AnyIPv4)) {
            statusLabel->setText("Failed to start server.");
            return;
        }
        serverPort = tcpServer->serverPort();
    }

    connect(tcpServer, &QTcpServer::newConnection, this, &SyncDialog::onNewConnection);

    // Inactivity guard: a client that connects but stalls (before or during
    // the session) must not hold the sync server open indefinitely.
    sessionTimer = new QTimer(this);
    sessionTimer->setSingleShot(true);
    connect(sessionTimer, &QTimer::timeout, this, [this]() {
        if (state != State::Done && state != State::Failed) {
            fail("Session timed out due to inactivity.");
        }
    });

    // Enumerate local IPv4 network interfaces
    const auto interfaces = QNetworkInterface::allInterfaces();
    int defaultIndex = -1;
    int currentIndex = 0;

    for (const auto &iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp) || (iface.flags() & QNetworkInterface::IsLoopBack))
            continue;

        for (const auto &entry : iface.addressEntries()) {
            QHostAddress addr = entry.ip();
            if (addr.protocol() == QAbstractSocket::IPv4Protocol && !addr.isLoopback()) {
                QString ipStr = addr.toString();
                QString displayName = QString("%1 (%2)").arg(ipStr, iface.humanReadableName());
                ipComboBox->addItem(displayName, ipStr);

                if (defaultIndex == -1 && (ipStr.startsWith("192.168.") || ipStr.startsWith("10.") || ipStr.startsWith("172.16."))) {
                    defaultIndex = currentIndex;
                }
                currentIndex++;
            }
        }
    }

    if (ipComboBox->count() == 0) {
        ipComboBox->addItem("127.0.0.1 (Localhost)", "127.0.0.1");
        defaultIndex = 0;
    }

    if (defaultIndex != -1) {
        ipComboBox->setCurrentIndex(defaultIndex);
    }

    connect(ipComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SyncDialog::onIpIndexChanged);

    updateQrPayload();
}

void SyncDialog::updateQrPayload() {
    QString ipAddress = ipComboBox->currentData().toString();
    if (ipAddress.isEmpty()) {
        ipAddress = "127.0.0.1";
    }

    currentQrText = QString("vsync2:%1:%2:%3")
                    .arg(ipAddress)
                    .arg(serverPort)
                    .arg(QString::fromLatin1(pskToBase64Url(pairingSecret)));

    generateQrCode(currentQrText);
    statusLabel->setText(QString("Scan the QR code with the mobile app to start Vault Sync.\nDesktop IP: %1 · Port: %2\nAllow port %2 through your firewall if prompted.")
                         .arg(ipAddress).arg(serverPort));
}

void SyncDialog::onPortChanged(int port) {
    if (port < 1 || port > 65535) return;
    QSettings settings("SecurePasswd_MGMT", "SecurePasswd_MGMT");
    settings.setValue("sync_port", port);

    // Re-bind only while no client is connected; mid-session changes are
    // ignored (the QR already carries the active port).
    if (state != State::AwaitingConnection || !tcpServer) return;
    tcpServer->close();
    serverPort = (quint16)port;
    if (!tcpServer->listen(QHostAddress::AnyIPv4, serverPort)) {
        if (!tcpServer->listen(QHostAddress::AnyIPv4)) {
            fail("Failed to restart the sync server on the chosen port.");
            return;
        }
        serverPort = tcpServer->serverPort();
        portSpinBox->blockSignals(true);
        portSpinBox->setValue((int)serverPort);
        portSpinBox->blockSignals(false);
        statusLabel->setText(QString("Preferred port %1 is busy — using port %2 for this session.")
                                 .arg(port).arg(serverPort));
    }
    updateQrPayload();
}

void SyncDialog::onIpIndexChanged(int /*index*/) {
    if (state == State::AwaitingConnection) {
        updateQrPayload();
    }
}

void SyncDialog::onCopySyncCodeClicked() {
    QClipboard *clipboard = QGuiApplication::clipboard();
    if (clipboard && !currentQrText.isEmpty()) {
        clipboard->setText(currentQrText);
        copyButton->setText("Copied!");
        QTimer::singleShot(2000, this, [this]() {
            copyButton->setText("Copy Sync Code");
        });
    }
}

SyncDialog::~SyncDialog() {
    if (sessionActive) {
        sync_session_zero(&session);
        sessionActive = false;
    }
    if (clientSocket) {
        clientSocket->disconnectFromHost();
    }
    // The 512-bit pairing secret and the ephemeral private key must not
    // linger in freed heap memory after the dialog closes.
    OPENSSL_cleanse(pairingSecret.data(), (size_t)pairingSecret.size());
    OPENSSL_cleanse(serverPriv, sizeof(serverPriv));
    if (sessionTimer) {
        sessionTimer->stop();
    }
    // Client tombstones kept for the GPG phase must not leak either.
    if (pendingRemoteTombs) {
        sync_tombstones_free(pendingRemoteTombs, pendingRemoteTombCount);
        pendingRemoteTombs = NULL;
        pendingRemoteTombCount = 0;
    }
}

void SyncDialog::generateQrCode(const QString &text) {
    using namespace qrcodegen;
    QrCode qr = QrCode::encodeText(text.toUtf8().constData(), QrCode::Ecc::MEDIUM);

    int scale = 8;
    int size = qr.getSize();
    int margin = 2;
    int imgSize = (size + 2 * margin) * scale;

    QImage image(imgSize, imgSize, QImage::Format_RGB32);
    image.fill(Qt::white);

    QPainter painter(&image);
    painter.setBrush(Qt::black);
    painter.setPen(Qt::NoPen);

    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            if (qr.getModule(x, y)) {
                painter.drawRect((x + margin) * scale, (y + margin) * scale, scale, scale);
            }
        }
    }

    qrLabel->setPixmap(QPixmap::fromImage(image));
}

void SyncDialog::onNewConnection() {
    if (clientSocket) {
        // Already in a session; reject additional connections.
        QTcpSocket *extra = tcpServer->nextPendingConnection();
        extra->abort();
        extra->deleteLater();
        return;
    }

    clientSocket = tcpServer->nextPendingConnection();
    if (!clientSocket) return;
    clientSocket->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(clientSocket, &QTcpSocket::readyRead, this, &SyncDialog::onReadyRead);
    connect(clientSocket, &QTcpSocket::disconnected, clientSocket, &QObject::deleteLater);
    connect(clientSocket, &QTcpSocket::destroyed, this, [this](QObject *) {
        clientSocket = nullptr;
    });

    statusLabel->setText("Connected. Authenticating…");
    state = State::AwaitClientHello;
    sessionTimer->start(SESSION_TIMEOUT_MS);
    sendServerHello();
}

void SyncDialog::sendServerHello() {
    if (sync_ephemeral_keygen(serverPub, serverPriv) != 0) {
        fail("Failed to generate handshake keys.");
        return;
    }

    // Wire hello: [version u8][ephemeral pubkey 32B]
    QByteArray hello;
    hello.append(static_cast<char>(SPSYNC_VERSION));
    hello.append(reinterpret_cast<const char *>(serverPub), SYNC_EPHEMERAL_LEN);
    clientSocket->write(hello);
}

void SyncDialog::setSummaryVariant(const QString &variant) {
    if (!summaryCard) return;
    summaryCard->setProperty("variant", variant);
    // Force the stylesheet to re-evaluate the dynamic property.
    summaryCard->style()->unpolish(summaryCard);
    summaryCard->style()->polish(summaryCard);
    summaryCard->update();
}

void SyncDialog::fail(const QString &message) {
    state = State::Failed;
    statusLabel->setText(QString("Vault Sync failed: %1").arg(message));
    setSummaryVariant("error");
    detailBox->hide();
    if (clientSocket && sessionActive) {
        // Best-effort: tell the mobile side why we aborted. Must happen
        // while the session keys are still alive.
        QByteArray msg = message.toUtf8();
        std::vector<unsigned char> out(5 + (size_t)msg.size() + SYNC_TAG_LEN + 16);
        size_t out_len = 0;
        if (sync_frame_encrypt(&session, SYNC_FRAME_ERROR,
                               reinterpret_cast<const unsigned char *>(msg.constData()),
                               (size_t)msg.size(), out.data(), out.size(), &out_len) == 0) {
            clientSocket->write(reinterpret_cast<const char *>(out.data()), (qint64)out_len);
            clientSocket->flush();
        }
    }
    if (sessionActive) {
        sync_session_zero(&session);
        sessionActive = false;
    }
    if (clientSocket) {
        clientSocket->disconnectFromHost();
    }
    // The client tombstones kept for the GPG phase must not leak either.
    if (pendingRemoteTombs) {
        sync_tombstones_free(pendingRemoteTombs, pendingRemoteTombCount);
        pendingRemoteTombs = NULL;
        pendingRemoteTombCount = 0;
    }
}

void SyncDialog::onReadyRead() {
    if (!clientSocket || state == State::Failed) return;
    sessionTimer->start(SESSION_TIMEOUT_MS);
    rxBuffer.append(clientSocket->readAll());
    processRxBuffer();
}

void SyncDialog::processRxBuffer() {
    // The client hello is a raw (unencrypted) message: [version u8][ephemeral 32B].
    if (state == State::AwaitClientHello) {
        if (rxBuffer.size() < 1 + SYNC_EPHEMERAL_LEN) return;
        if ((unsigned char)rxBuffer.at(0) != SPSYNC_VERSION) {
            fail("The mobile app uses an incompatible sync version. Please update both apps.");
            return;
        }
        uint8_t clientPub[SYNC_EPHEMERAL_LEN];
        std::copy(rxBuffer.constData() + 1, rxBuffer.constData() + 1 + SYNC_EPHEMERAL_LEN,
                  clientPub);
        rxBuffer.remove(0, 1 + SYNC_EPHEMERAL_LEN);

        if (sync_session_derive(SYNC_ROLE_SERVER,
                                reinterpret_cast<const unsigned char *>(pairingSecret.constData()),
                                clientPub, serverPub, serverPriv,
                                &session) != 0) {
            fail("Handshake key agreement failed.");
            return;
        }
        sessionActive = true;

        // Key confirmation: send our transcript hash encrypted under the
        // freshly derived session keys. The client replies with its own.
        std::vector<unsigned char> out(5 + 32 + SYNC_TAG_LEN + 16);
        size_t out_len = 0;
        if (sync_frame_encrypt(&session, SYNC_FRAME_CONFIRM,
                               session.transcript_hash, 32,
                               out.data(), out.size(), &out_len) != 0) {
            fail("Failed to send key confirmation.");
            return;
        }
        clientSocket->write(reinterpret_cast<const char *>(out.data()), (qint64)out_len);
        clientSocket->flush();
        state = State::AwaitConfirm;
    }

    while (clientSocket && state != State::Failed && state != State::Done) {
        if (rxBuffer.size() < 5) return;

        unsigned int ctLen = ((unsigned char)rxBuffer.at(1) << 24) |
                             ((unsigned char)rxBuffer.at(2) << 16) |
                             ((unsigned char)rxBuffer.at(3) << 8) |
                             (unsigned char)rxBuffer.at(4);
        if (ctLen > SYNC_FRAME_MAX) {
            fail("Received an oversized frame.");
            return;
        }
        if ((unsigned int)rxBuffer.size() < 5 + ctLen) return;

        QByteArray frame = rxBuffer.left(5 + (int)ctLen);
        rxBuffer.remove(0, 5 + (int)ctLen);
        handleFrame(frame);
    }
}

void SyncDialog::handleFrame(const QByteArray &frame) {
    size_t expected = frame.size() > 5 ? (size_t)frame.size() - 5 - SYNC_TAG_LEN : 0;
    std::vector<unsigned char> payload(expected + 16);

    size_t payload_len = 0;
    sync_frame_type_t expectedType;
    switch (state) {
        case State::AwaitConfirm:  expectedType = SYNC_FRAME_CONFIRM; break;
        case State::AwaitSnapshot: expectedType = SYNC_FRAME_SNAPSHOT; break;
        case State::AwaitGpg:      expectedType = SYNC_FRAME_GPG; break;
        case State::AwaitAck:      expectedType = SYNC_FRAME_ACK; break;
        default:
            fail("Unexpected message during sync.");
            return;
    }
    if (sync_frame_decrypt(&session, (uint8_t)expectedType,
                           reinterpret_cast<const unsigned char *>(frame.constData()),
                           (size_t)frame.size(), payload.data(), payload.size(),
                           &payload_len) != 0) {
        fail("Decryption failed (wrong pairing key, tampered data, or a replayed session).");
        return;
    }

    switch (state) {
    case State::AwaitConfirm: {
        if (payload_len != 32 ||
            sync_ct_equal(payload.data(), session.transcript_hash, 32) != 1) {
            fail("Key confirmation failed. The mobile client used a different pairing key.");
            return;
        }
        state = State::AwaitSnapshot;
        statusLabel->setText("Authenticated. Receiving vault from mobile…");
        break;
    }
    case State::AwaitSnapshot: {
        sync_entry_t *remote_entries = NULL;
        int remote_count = 0;
        sync_tombstone_t *remote_tombs = NULL;
        int remote_tomb_count = 0;
        if (sync_snapshot_deserialize(payload.data(), payload_len,
                                      &remote_entries, &remote_count,
                                      &remote_tombs, &remote_tomb_count) != 0) {
            fail("Received an invalid vault snapshot.");
            return;
        }

        int local_count = 0, local_tomb_count = 0;
        PasswordEntry *local_full = database_get_all_entries_full(&local_count);
        sync_tombstone_t *local_tombs = database_get_tombstones(&local_tomb_count);
        if (!local_full) {
            // database_get_all_entries_full returns NULL for an empty vault too.
            local_full = NULL;
            local_count = 0;
        }

        std::vector<sync_entry_t> local_entries((size_t)local_count);
        for (int i = 0; i < local_count; i++) {
            local_entries[(size_t)i].service = local_full[i].service;
            local_entries[(size_t)i].username = local_full[i].username;
            local_entries[(size_t)i].password = local_full[i].password;
            local_entries[(size_t)i].totp_secret = local_full[i].totp_secret;
            local_entries[(size_t)i].recovery_codes = local_full[i].recovery_codes;
            local_entries[(size_t)i].updated_at = local_full[i].updated_at;
        }

        sync_merge_report_t report;
        if (sync_merge_vaults(local_entries.data(), local_count,
                              remote_entries, remote_count,
                              local_tombs, local_tomb_count,
                              remote_tombs, remote_tomb_count,
                              &report) != 0) {
            sync_entries_free(remote_entries, remote_count);
            sync_tombstones_free(remote_tombs, remote_tomb_count);
            sync_tombstones_free(local_tombs, local_tomb_count);
            free_password_entries(local_full, local_count);
            fail("Internal error while merging vaults.");
            return;
        }

        QString summary;
        if (!applyMergeReport(report, &summary)) {
            sync_merge_report_free(&report);
            sync_entries_free(remote_entries, remote_count);
            sync_tombstones_free(remote_tombs, remote_tomb_count);
            sync_tombstones_free(local_tombs, local_tomb_count);
            free_password_entries(local_full, local_count);
            fail("Failed to apply merged changes to the local vault.");
            return;
        }

        sync_entries_free(remote_entries, remote_count);
        free_password_entries(local_full, local_count);
        sync_merge_report_free(&report);

        /* Client tombstones are still needed by the GPG phase (they carry
         * the client's GPG deletions) — keep them, free local ones (the
         * GPG phase re-reads fresh tombstones after the apply above). */
        pendingRemoteTombs = remote_tombs;
        pendingRemoteTombCount = remote_tomb_count;
        pendingSummary = summary;

        // Send the merged vault snapshot back to the mobile client
        // immediately — the client blocks waiting for it before it
        // can proceed to the GPG phase.
        sendMergedSnapshot();
        if (state == State::Failed) return;

        state = State::AwaitGpg;
        statusLabel->setText("Merged vault sent. Receiving OpenPGP keys…");
        break;
    }
    case State::AwaitGpg: {
        /* Client's OpenPGP key store section (SPSNAP03). */
        sync_gpg_key_t *remote_keys = NULL;
        int remote_key_count = 0;
        if (sync_gpg_deserialize(payload.data(), payload_len,
                                 &remote_keys, &remote_key_count) != 0) {
            fail("Received an invalid OpenPGP key section.");
            return;
        }

        int local_key_count = 0, tomb_count = 0;
        GpgKey *local_keys = database_gpg_get_all(&local_key_count);
        sync_tombstone_t *tombs = database_get_tombstones(&tomb_count);

        std::vector<sync_gpg_key_t> local_section((size_t)local_key_count);
        for (int i = 0; i < local_key_count; i++) {
            sync_gpg_key_init(&local_section[(size_t)i]);
            local_section[(size_t)i].label = strdup(local_keys[i].label ? local_keys[i].label : "");
            local_section[(size_t)i].email = strdup(local_keys[i].email ? local_keys[i].email : "");
            local_section[(size_t)i].key_id = strdup(local_keys[i].key_id ? local_keys[i].key_id : "");
            local_section[(size_t)i].public_key = strdup(local_keys[i].public_key ? local_keys[i].public_key : "");
            local_section[(size_t)i].private_key = strdup(local_keys[i].private_key ? local_keys[i].private_key : "");
            local_section[(size_t)i].updated_at = local_keys[i].updated_at;
        }

        sync_gpg_merge_report_t grep;
        if (sync_merge_gpg_keys(local_section.data(), local_key_count,
                                remote_keys, remote_key_count,
                                tombs, tomb_count,
                                pendingRemoteTombs, pendingRemoteTombCount,
                                &grep) != 0) {
            sync_gpg_keys_free(remote_keys, remote_key_count);
            sync_gpg_keys_wipe(local_section.data(), local_key_count);
            sync_tombstones_free(tombs, tomb_count);
            database_gpg_free(local_keys, local_key_count);
            fail("Internal error while merging OpenPGP keys.");
            return;
        }

        QString summary;
        if (!applyGpgMergeReport(grep, &summary)) {
            sync_gpg_merge_report_free(&grep);
            sync_gpg_keys_free(remote_keys, remote_key_count);
            sync_gpg_keys_wipe(local_section.data(), local_key_count);
            sync_tombstones_free(tombs, tomb_count);
            sync_tombstones_free(pendingRemoteTombs, pendingRemoteTombCount);
            pendingRemoteTombs = NULL;
            pendingRemoteTombCount = 0;
            database_gpg_free(local_keys, local_key_count);
            fail("Failed to apply merged OpenPGP key changes.");
            return;
        }
        QString fullSummary = pendingSummary;
        if (!summary.isEmpty()) {
            if (!fullSummary.isEmpty()) fullSummary += '\n';
            fullSummary += summary;
        }
        detailBox->setPlainText(fullSummary);
        detailBox->show();
        summaryCard->show();
        setSummaryVariant("success");

        sync_gpg_keys_free(remote_keys, remote_key_count);
        sync_gpg_keys_wipe(local_section.data(), local_key_count);
        sync_tombstones_free(tombs, tomb_count);
        sync_tombstones_free(pendingRemoteTombs, pendingRemoteTombCount);
        pendingRemoteTombs = NULL;
        pendingRemoteTombCount = 0;
        database_gpg_free(local_keys, local_key_count);
        sync_gpg_merge_report_free(&grep);

        sendMergedGpgKeys();
        if (state == State::Failed) return;

        state = State::AwaitAck;
        statusLabel->setText("Merging complete. Awaiting mobile acknowledgement…");
        break;
    }
    case State::AwaitAck: {
        state = State::Done;
        sessionTimer->stop();
        statusLabel->setText("Vault Sync complete! Changes are merged on both devices.");
        if (sessionActive) {
            sync_session_zero(&session);
            sessionActive = false;
        }
        clientSocket->disconnectFromHost();
        break;
    }
    default:
        break;
    }
}

bool SyncDialog::applyMergeReport(const sync_merge_report_t &report, QString *summary) {
    QStringList lines;
    // Headline uses the cross-platform summary format (DESIGN_TOKENS.md);
    // the same string is shown by the mobile app.
    lines << QString("Added %1 · Updated %2 · Deleted %3 · Conflicts %4")
                 .arg(report.added).arg(report.updated)
                 .arg(report.deleted).arg(report.conflicts);
    lines << QString("Unchanged: %1").arg(report.identical);
    lines << QString();

    for (int i = 0; i < report.result_count; i++) {
        const sync_merge_result_t *r = &report.results[i];
        QString identity = QString("%1 / %2").arg(r->service).arg(r->username);
        switch (r->action) {
        case SYNC_MERGE_APPLY_REMOTE: {
            // Winner data comes from the mobile side; preserve its timestamp.
            PasswordEntry entry;
            memset(&entry, 0, sizeof(entry));
            entry.service = r->winner.service;
            entry.username = r->winner.username;
            entry.password = r->winner.password;
            entry.totp_secret = r->winner.totp_secret;
            entry.recovery_codes = r->winner.recovery_codes;
            entry.updated_at = r->winner.updated_at;

            PasswordEntry *existing = database_get_entry_by_identity(r->service, r->username);
            if (existing) {
                entry.id = existing->id;
                free_password_entries(existing, 1);
                if (database_update_entry(&entry) != 0) return false;
            } else {
                if (database_add_entry(&entry) < 0) return false;
            }
            if (r->is_conflict) {
                lines << QString("  conflict: %1 — mobile version (newer) applied").arg(identity);
            }
            break;
        }
        case SYNC_MERGE_KEEP_LOCAL:
            if (r->is_conflict) {
                lines << QString("  conflict: %1 — desktop version (newer) kept").arg(identity);
            }
            break;
        case SYNC_MERGE_DELETED: {
            PasswordEntry *existing = database_get_entry_by_identity(r->service, r->username);
            if (existing) {
                int id = existing->id;
                free_password_entries(existing, 1);
                if (database_delete_entry(id) != 0) return false;
            }
            lines << QString("  deleted: %1 (removed on mobile)").arg(identity);
            break;
        }
        case SYNC_MERGE_IDENTICAL:
        case SYNC_MERGE_IGNORED:
        default:
            break;
        }
    }

    *summary = lines.join('\n');
    return true;
}

void SyncDialog::sendMergedSnapshot() {
    // The full post-merge local state becomes the snapshot for the mobile side.
    int local_count = 0, local_tomb_count = 0;
    PasswordEntry *local_full = database_get_all_entries_full(&local_count);
    sync_tombstone_t *local_tombs = database_get_tombstones(&local_tomb_count);

    std::vector<sync_entry_t> entries((size_t)local_count);
    for (int i = 0; i < local_count; i++) {
        sync_entry_init(&entries[(size_t)i]);
        entries[(size_t)i].service = strdup(local_full[i].service ? local_full[i].service : "");
        entries[(size_t)i].username = strdup(local_full[i].username ? local_full[i].username : "");
        entries[(size_t)i].password = strdup(local_full[i].password ? local_full[i].password : "");
        entries[(size_t)i].totp_secret = strdup(local_full[i].totp_secret ? local_full[i].totp_secret : "");
        entries[(size_t)i].recovery_codes = strdup(local_full[i].recovery_codes ? local_full[i].recovery_codes : "");
        entries[(size_t)i].updated_at = local_full[i].updated_at;
    }

    uint8_t *snapshot = NULL;
    size_t snapshot_len = 0;
    int rc = sync_snapshot_serialize(entries.data(), local_count,
                                     local_tombs, local_tomb_count,
                                     &snapshot, &snapshot_len);

    /* entries is a std::vector buffer: wipe elements only, do not free(). */
    sync_entries_wipe(entries.data(), local_count);
    sync_tombstones_free(local_tombs, local_tomb_count);
    free_password_entries(local_full, local_count);

    if (rc != 0) {
        fail("Failed to serialize the merged vault.");
        return;
    }

    std::vector<unsigned char> out(5 + snapshot_len + SYNC_TAG_LEN + 16);
    size_t out_len = 0;
    rc = sync_frame_encrypt(&session, SYNC_FRAME_SNAPSHOT, snapshot, snapshot_len,
                            out.data(), out.size(), &out_len);
    if (snapshot) {
        memset(snapshot, 0, snapshot_len);
        free(snapshot);
    }
    if (rc != 0) {
        fail("Failed to encrypt the merged vault.");
        return;
    }

    clientSocket->write(reinterpret_cast<const char *>(out.data()), (qint64)out_len);
    clientSocket->flush();
}

bool SyncDialog::applyGpgMergeReport(const sync_gpg_merge_report_t &report, QString *summary) {
    QStringList lines;
    lines << QString("Keys added %1 · Updated %2 · Deleted %3 · Conflicts %4")
                 .arg(report.added).arg(report.updated)
                 .arg(report.deleted).arg(report.conflicts);

    for (int i = 0; i < report.result_count; i++) {
        const sync_gpg_merge_result_t *r = &report.results[i];
        switch (r->action) {
        case SYNC_MERGE_APPLY_REMOTE: {
            // Winner data comes from the mobile side; preserve its timestamp.
            GpgKey key;
            memset(&key, 0, sizeof(key));
            key.label = r->winner.label;
            key.email = r->winner.email;
            key.key_id = r->winner.key_id;
            key.public_key = r->winner.public_key;
            key.private_key = r->winner.private_key;
            key.updated_at = r->winner.updated_at;

            // Find the local row by label (labels are the merge identity).
            const QString winnerLabel =
                QString::fromUtf8(r->winner.label ? r->winner.label : "");
            int count = 0;
            GpgKey *keys = database_gpg_get_all(&count);
            int localId = 0;
            for (int j = 0; j < count; j++) {
                if (keys[j].label &&
                    QString::fromUtf8(keys[j].label).compare(winnerLabel, Qt::CaseInsensitive) == 0) {
                    localId = keys[j].id;
                    break;
                }
            }
            database_gpg_free(keys, count);

            if (localId > 0) {
                key.id = localId;
                if (database_gpg_update(&key) != 0) return false;
            } else {
                if (database_gpg_add(&key) < 0) return false;
            }
            if (r->is_conflict) {
                lines << QString("  conflict: %1 — mobile version (newer) applied").arg(r->label);
            }
            break;
        }
        case SYNC_MERGE_KEEP_LOCAL:
            if (r->is_conflict) {
                lines << QString("  conflict: %1 — desktop version (newer) kept").arg(r->label);
            }
            break;
        case SYNC_MERGE_DELETED: {
            // Locate by label; database_gpg_delete records the tombstone.
            const QString deletedLabel =
                QString::fromUtf8(r->label ? r->label : "");
            int count = 0;
            GpgKey *keys = database_gpg_get_all(&count);
            int localId = 0;
            for (int j = 0; j < count; j++) {
                if (keys[j].label &&
                    QString::fromUtf8(keys[j].label).compare(deletedLabel, Qt::CaseInsensitive) == 0) {
                    localId = keys[j].id;
                    break;
                }
            }
            database_gpg_free(keys, count);
            if (localId > 0 && database_gpg_delete(localId) != 0) return false;
            lines << QString("  deleted: %1 (removed on mobile)").arg(r->label);
            break;
        }
        case SYNC_MERGE_IDENTICAL:
        case SYNC_MERGE_IGNORED:
        default:
            break;
        }
    }

    *summary = lines.join('\n');
    return true;
}

void SyncDialog::sendMergedGpgKeys() {
    /* The full post-merge local key store becomes the client's merged view. */
    int key_count = 0;
    GpgKey *local_keys = database_gpg_get_all(&key_count);

    std::vector<sync_gpg_key_t> keys((size_t)key_count);
    for (int i = 0; i < key_count; i++) {
        sync_gpg_key_init(&keys[(size_t)i]);
        keys[(size_t)i].label = strdup(local_keys[i].label ? local_keys[i].label : "");
        keys[(size_t)i].email = strdup(local_keys[i].email ? local_keys[i].email : "");
        keys[(size_t)i].key_id = strdup(local_keys[i].key_id ? local_keys[i].key_id : "");
        keys[(size_t)i].public_key = strdup(local_keys[i].public_key ? local_keys[i].public_key : "");
        keys[(size_t)i].private_key = strdup(local_keys[i].private_key ? local_keys[i].private_key : "");
        keys[(size_t)i].updated_at = local_keys[i].updated_at;
    }

    uint8_t *section = NULL;
    size_t section_len = 0;
    int rc = sync_gpg_serialize(keys.data(), key_count, &section, &section_len);

    /* keys is a std::vector buffer: wipe elements only, do not free(). */
    sync_gpg_keys_wipe(keys.data(), key_count);
    database_gpg_free(local_keys, key_count);

    if (rc != 0) {
        fail("Failed to serialize the OpenPGP key store.");
        return;
    }

    std::vector<unsigned char> out(5 + section_len + SYNC_TAG_LEN + 16);
    size_t out_len = 0;
    rc = sync_frame_encrypt(&session, SYNC_FRAME_GPG, section, section_len,
                            out.data(), out.size(), &out_len);
    if (section) {
        memset(section, 0, section_len);
        free(section);
    }
    if (rc != 0) {
        fail("Failed to encrypt the OpenPGP key store.");
        return;
    }

    clientSocket->write(reinterpret_cast<const char *>(out.data()), (qint64)out_len);
    clientSocket->flush();
}
