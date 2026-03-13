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
#include "qrcodegen.hpp"

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

    char dirPath[2048]; // flawfinder: ignore
    get_config_path(dirPath, sizeof(dirPath));
    QString dbPath = QString::fromUtf8(dirPath) + "/vault.db";

    FILE *f1 = fopen(dbPath.toUtf8().constData(), "rb");
    if (!f1) {
        statusLabel->setText("Error: Could not open vault for reading.");
        clientConnection->disconnectFromHost();
        return;
    }
    fseek(f1, 0, SEEK_END);
    size_t db_size = ftell(f1);
    fclose(f1);

    char saltPath[2048];
    snprintf(saltPath, sizeof(saltPath), "%s.salt", dbPath.toUtf8().constData());
    FILE *f2 = fopen(saltPath, "rb");
    if (!f2) {
        statusLabel->setText("Error: Could not open salt for reading.");
        clientConnection->disconnectFromHost();
        return;
    }
    fseek(f2, 0, SEEK_END);
    size_t salt_size = ftell(f2);
    fclose(f2);

    size_t total_size = 4 + db_size + 4 + salt_size;
    size_t output_size = total_size + SYNC_NONCE_LEN + SYNC_TAG_LEN + 1024;
    unsigned char *output = (unsigned char*)malloc(output_size);
    if (!output) {
        statusLabel->setText("Error: Memory allocation failed.");
        clientConnection->disconnectFromHost();
        return;
    }

    size_t actual_size = 0;
    if (sync_encrypt_vault(dbPath.toUtf8().constData(), output, &actual_size, (unsigned char*)syncKey.constData()) != 0) {
        statusLabel->setText("Error: Encryption failed.");
        free(output);
        clientConnection->disconnectFromHost();
        return;
    }

    clientConnection->write(reinterpret_cast<const char*>(output), actual_size);
    clientConnection->disconnectFromHost();
    free(output);
    statusLabel->setText("Sync complete.");
}
