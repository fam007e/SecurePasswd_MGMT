#ifndef HEALTHCHECKDIALOG_H
#define HEALTHCHECKDIALOG_H

#include <QDialog>
#include <QVector>
#include <QFutureWatcher>
#include "passwordentry.h"

class QTreeWidget;
class QTreeWidgetItem;

// Struct to pass HIBP results between threads
struct PwnedResult {
    QString serviceName;
    int pwnCount;
};
Q_DECLARE_METATYPE(PwnedResult)

class HealthCheckDialog : public QDialog
{
    Q_OBJECT

public:
    explicit HealthCheckDialog(const QVector<GUIPasswordEntry> &entries, QWidget *parent = nullptr);

private slots:
    void handlePwnedResult(PwnedResult result);
    void handleHibpFinished();

private:
    void runLocalChecks();
    void startHibpChecks();
    void addIssue(const QString &category, const QString &serviceName, const QString &details);

    const QVector<GUIPasswordEntry> &m_entries;
    QTreeWidget *treeWidget;
    QHash<QString, QTreeWidgetItem*> categoryItems;
    QFutureWatcher<void> m_hibpWatcher;
};

#endif // HEALTHCHECKDIALOG_H