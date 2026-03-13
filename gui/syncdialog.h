#ifndef SYNCDIALOG_H
#define SYNCDIALOG_H

#include <QDialog>
#include <QTcpServer>
#include <QTcpSocket>

class QLabel;

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
