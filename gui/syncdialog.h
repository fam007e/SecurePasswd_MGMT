#ifndef SYNCDIALOG_H
#define SYNCDIALOG_H

#include <QDialog>
#include <QTcpServer>
#include <QTcpSocket>
#include <QByteArray>

extern "C" {
#include "sync_protocol.h"
}

class QLabel;
class QPlainTextEdit;
class QTimer;
class QComboBox;
class QPushButton;
class QSpinBox;
class QFrame;

/**
 * @class SyncDialog
 * @brief Manages the secure 2-way mobile synchronization process.
 *
 * Generates a fresh 512-bit pairing secret, displays it as a QR code
 * (vsync2: payload), and runs an authenticated encrypted session with the
 * mobile client: the mobile sends its vault snapshot, the desktop merges it
 * into the local vault (newer-wins, conflicts reviewed in the summary) and
 * sends the merged snapshot back. All traffic is protected by an X25519 +
 * PSK-authenticated handshake with per-direction AEAD frames.
 */
/* Max seconds a sync session may stay silent before being aborted. */
static const int SESSION_TIMEOUT_MS = 30000;

class SyncDialog : public QDialog {
    Q_OBJECT

public:
    explicit SyncDialog(QWidget *parent = nullptr);
    ~SyncDialog();

private slots:
    void onNewConnection();
    void onReadyRead();
    void onIpIndexChanged(int index);
    void onPortChanged(int port);
    void onCopySyncCodeClicked();

private:
    enum class State {
        AwaitingConnection,
        AwaitClientHello, /* raw [version u8][client ephemeral 32B] */
        AwaitConfirm,     /* waiting for client key-confirmation frame */
        AwaitSnapshot,    /* waiting for the client's vault snapshot */
        AwaitGpg,         /* waiting for the client's OpenPGP key section */
        AwaitAck,         /* waiting for the final acknowledgement */
        Done,
        Failed
    };

    void updateQrPayload();
    void generateQrCode(const QString &text);
    void sendServerHello();
    void processRxBuffer();
    void handleFrame(const QByteArray &frame);
    void fail(const QString &message);
    void setSummaryVariant(const QString &variant);
    bool applyMergeReport(const sync_merge_report_t &report, QString *summary);
    bool applyGpgMergeReport(const sync_gpg_merge_report_t &report, QString *summary);
    void sendMergedSnapshot();
    void sendMergedGpgKeys();

    /* Client tombstones from the snapshot phase, kept alive until the GPG
     * phase (they carry the client's GPG deletions), then freed. */
    sync_tombstone_t *pendingRemoteTombs = NULL;
    int pendingRemoteTombCount = 0;
    QString pendingSummary;

    QLabel *qrLabel;
    QLabel *statusLabel;
    QComboBox *ipComboBox;
    QSpinBox *portSpinBox = nullptr;
    QPushButton *copyButton;
    QPushButton *closeButton;
    QPlainTextEdit *detailBox;
    QFrame *summaryCard = nullptr;
    QTimer *sessionTimer = nullptr;
    QTcpServer *tcpServer;
    QTcpSocket *clientSocket = nullptr;

    quint16 serverPort = 33261;
    QString currentQrText;

    State state = State::AwaitingConnection;
    QByteArray pairingSecret; /* 64-byte (512-bit) one-time PSK */
    QByteArray rxBuffer;

    uint8_t serverPub[SYNC_EPHEMERAL_LEN];
    uint8_t serverPriv[SYNC_EPHEMERAL_LEN];
    sync_session_t session;
    bool sessionActive = false;
};

#endif // SYNCDIALOG_H
