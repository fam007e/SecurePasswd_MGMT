#ifndef GUIPASSWORDENTRY_H
#define GUIPASSWORDENTRY_H

#include <QString>

struct GUIPasswordEntry {
    int id = 0;
    QString service;
    QString username;
    // Sensitive fields (password, totpSecret, recoveryCodes)
    // are now fetched on-demand from the database to improve memory security.
};

#endif // GUIPASSWORDENTRY_H
