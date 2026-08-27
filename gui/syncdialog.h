#ifndef SYNCDIALOG_H
#define SYNCDIALOG_H

#include <QDialog>
#include <QTcpServer>
#include <QTcpSocket>

class QLabel;

/**
 * @class SyncDialog
 * @brief Manages the secure mobile synchronization process.
 *
 * Generates a one-time synchronization key, displays it as a QR code,
 * and starts a temporary encrypted server to transfer the vault to a mobile device.
 */
class SyncDialog : public QDialog {
    Q_OBJECT

public:
    explicit SyncDialog(QWidget *parent = nullptr);
    ~SyncDialog();

private slots:
    void onNewConnection();

private:
    void generateQrCode(const QString &text);

    QLabel *qrLabel;
    QLabel *statusLabel;
    QTcpServer *tcpServer;
    QByteArray syncKey;
};

#endif // SYNCDIALOG_H
