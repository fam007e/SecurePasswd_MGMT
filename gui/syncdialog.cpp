#include "syncdialog.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QTcpSocket>
#include <QPainter>
#include <QImage>
#include <QPixmap>
#include <QHostAddress>
#include <QFile>
#include <vector>
#include "qrcodegen/qrcodegen.hpp"

extern "C" {
#include "sync_service.h"
#include "platform_paths.h"
#include <openssl/rand.h>
}

SyncDialog::SyncDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Sync to Mobile");
    setMinimumSize(400, 500);

    QVBoxLayout *layout = new QVBoxLayout(this);

    qrLabel = new QLabel(this);
    qrLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(qrLabel);

    statusLabel = new QLabel("Initializing...", this);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    // Generate 32-byte key
    syncKey.resize(SYNC_KEY_LEN);
    RAND_bytes(reinterpret_cast<unsigned char*>(syncKey.data()), SYNC_KEY_LEN);

    // Start TCP Server
    tcpServer = new QTcpServer(this);
    if (!tcpServer->listen(QHostAddress::Any)) {
        statusLabel->setText("Failed to start server.");
        return;
    }

    connect(tcpServer, &QTcpServer::newConnection, this, &SyncDialog::onNewConnection);

    // Find local IP
    QString ipAddress;
    QList<QHostAddress> ipAddressesList = QNetworkInterface::allAddresses();
    for (int i = 0; i < ipAddressesList.size(); ++i) {
        if (ipAddressesList.at(i) != QHostAddress::LocalHost &&
            ipAddressesList.at(i).toIPv4Address()) {
            ipAddress = ipAddressesList.at(i).toString();
            break;
        }
    }
    if (ipAddress.isEmpty()) {
        ipAddress = QHostAddress(QHostAddress::LocalHost).toString();
    }

    QString qrText = QString("vsync:%1:%2:%3")
                     .arg(ipAddress)
                     .arg(tcpServer->serverPort())
                     .arg(QString(syncKey.toHex()));

    generateQrCode(qrText);
    statusLabel->setText("Scan QR code with your mobile app to sync.");
}

SyncDialog::~SyncDialog() {
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
    QTcpSocket *clientConnection = tcpServer->nextPendingConnection();
    connect(clientConnection, &QAbstractSocket::disconnected,
            clientConnection, &QObject::deleteLater);

    statusLabel->setText("Client connected. Encrypting and sending vault...");

    std::vector<char> dirPath(4096);
    get_config_path(dirPath.data(), dirPath.size());
    QString dbPath = QString::fromUtf8(dirPath.data()) + "/vault.db";

    QFile f1(dbPath);
    if (!f1.exists()) {
        statusLabel->setText("Error: Could not open vault for reading.");
        clientConnection->disconnectFromHost();
        return;
    }
    size_t db_size = (size_t)f1.size();

    QString saltPath = dbPath + ".salt";
    QFile f2(saltPath);
    if (!f2.exists()) {
        statusLabel->setText("Error: Could not open salt for reading.");
        clientConnection->disconnectFromHost();
        return;
    }
    size_t salt_size = (size_t)f2.size();

    size_t total_size = 4 + db_size + 4 + salt_size;
    size_t output_size = total_size + SYNC_NONCE_LEN + SYNC_TAG_LEN + 1024;
    std::vector<unsigned char> output(output_size);

    size_t actual_size = 0;
    if (sync_encrypt_vault(dbPath.toUtf8().constData(), output.data(), &actual_size, (unsigned char*)syncKey.constData()) != 0) {
        statusLabel->setText("Error: Encryption failed.");
        clientConnection->disconnectFromHost();
        return;
    }

    clientConnection->write(reinterpret_cast<const char*>(output.data()), (qint64)actual_size);
    clientConnection->disconnectFromHost();
    statusLabel->setText("Sync complete.");
}
