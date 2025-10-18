#ifndef GUIPASSWORDENTRY_H
#define GUIPASSWORDENTRY_H

#include <QString>

struct GUIPasswordEntry {
    int id;
    QString service;
    QString username;
    QString password;
    QString totpSecret;
};

#endif // GUIPASSWORDENTRY_H