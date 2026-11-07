#ifndef THEMES_H
#define THEMES_H

#include <QString>

/**
 * @brief Palette registry for the desktop app.
 *
 * Each palette provides a dark and a light token set substituted into
 * gui/theme_template.qss. Values are documented in docs/DESIGN_TOKENS.md
 * and mirrored by the Android app (ui/theme/Color.kt). Adding a palette
 * means adding one ThemeTokens pair here — no styling code changes.
 */
struct ThemeTokens {
    QString background;     /* window background */
    QString surface;        /* cards, inputs, lists, toolbar */
    QString surfaceHover;   /* item hover */
    QString outline;        /* borders, pressed list item bg */
    QString onSurface;      /* text */
    QString onSurfaceBright;/* text on primary/selected surfaces */
    QString primary;        /* accent: progress, focus rings, checked */
    QString primaryHover;   /* button hover */
    QString primaryActive;  /* button pressed */
    QString success;        /* success card border */
    QString error;          /* error card border */
    QString textDisabled;   /* disabled controls */
};

struct Palette {
    const char *id;      /* stable settings key */
    const char *name;    /* user-visible name */
    ThemeTokens dark;
    ThemeTokens light;
};

/* Number of palettes in the registry. */
int paletteCount();

/* Palette at index (0 <= index < paletteCount()). */
const Palette &paletteAt(int index);

/* Lookup by settings key; falls back to Nord when unknown. */
const Palette &paletteById(const QString &id);

/* Substitutes the tokens into the theme template. */
QString buildStyleSheet(const Palette &palette, bool dark);

#endif // THEMES_H
