#include "themes.h"

#include <QResource>

/* Palette values are documented in docs/DESIGN_TOKENS.md. */

static const Palette kPalettes[] = {
    {
        "nord", "Nord",
        /* dark — Nord */
        {"#2E3440", "#3B4252", "#434C5E", "#4C566A", "#D8DEE9", "#ECEFF4",
         "#88C0D0", "#5E81AC", "#81A1C1", "#A3BE8C", "#BF616A", "#7B88A1"},
        /* light — Snow Storm + app-icon accent */
        {"#ECEFF4", "#FFFFFF", "#E5E9F0", "#D8DEE9", "#434343", "#FFFFFF",
         "#d97dbc", "#c77575", "#8b8484", "#A3BE8C", "#BF616A", "#A5A9B0"},
    },
    {
        "dracula", "Dracula",
        /* dark — Dracula */
        {"#282A36", "#343746", "#3B3D4E", "#44475A", "#F8F8F2", "#FFFFFF",
         "#BD93F9", "#9D7BE8", "#6272A4", "#50FA7B", "#FF5555", "#6272A4"},
        /* light — Dracula Paper (softened Dracula hues on paper) */
        {"#F8F8F2", "#FFFFFF", "#E6E6E0", "#D8D8D0", "#3B3D4E", "#282A36",
         "#6C4FC4", "#5A3FB0", "#44475A", "#2EA043", "#D0334A", "#A8A8A0"},
    },
    {
        "solarized", "Solarized",
        /* dark — Solarized Dark */
        {"#002B36", "#073642", "#0E4450", "#586E75", "#93A1A1", "#EEE8D5",
         "#268BD2", "#1E6FA8", "#6C71C4", "#859900", "#DC322F", "#657B83"},
        /* light — Solarized Light */
        {"#FDF6E3", "#EEE8D5", "#E4DDC8", "#93A1A1", "#586E75", "#073642",
         "#268BD2", "#1E6FA8", "#6C71C4", "#859900", "#DC322F", "#93A1A1"},
    },
};

static const int kPaletteCount = sizeof(kPalettes) / sizeof(kPalettes[0]);

int paletteCount() {
    return kPaletteCount;
}

const Palette &paletteAt(int index) {
    if (index < 0 || index >= kPaletteCount) index = 0;
    return kPalettes[index];
}

const Palette &paletteById(const QString &id) {
    for (int i = 0; i < kPaletteCount; i++) {
        if (id == QLatin1String(kPalettes[i].id)) return kPalettes[i];
    }
    return kPalettes[0]; /* Nord fallback */
}

QString buildStyleSheet(const Palette &palette, bool dark) {
    const ThemeTokens &t = dark ? palette.dark : palette.light;

    /* The template ships inside the executable (Qt resource system) — no
     * filesystem access at all. Read via QResource so there is no open()
     * call for static analysis to weigh. */
    QResource templateRes(QStringLiteral(":/theme_template.qss"));
    if (!templateRes.isValid()) {
        return QString();
    }
    QString css = QString::fromUtf8(templateRes.uncompressedData());

    css.replace(QStringLiteral("@background@"), t.background);
    css.replace(QStringLiteral("@surface@"), t.surface);
    css.replace(QStringLiteral("@surfaceHover@"), t.surfaceHover);
    css.replace(QStringLiteral("@outline@"), t.outline);
    css.replace(QStringLiteral("@onSurface@"), t.onSurface);
    css.replace(QStringLiteral("@onSurfaceBright@"), t.onSurfaceBright);
    css.replace(QStringLiteral("@primary@"), t.primary);
    css.replace(QStringLiteral("@primaryHover@"), t.primaryHover);
    css.replace(QStringLiteral("@primaryActive@"), t.primaryActive);
    css.replace(QStringLiteral("@success@"), t.success);
    css.replace(QStringLiteral("@error@"), t.error);
    css.replace(QStringLiteral("@textDisabled@"), t.textDisabled);
    return css;
}
