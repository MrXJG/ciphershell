#include "gui/main_window.h"

#include <QApplication>
#include <QString>

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  app.setApplicationName(QStringLiteral("gmssh-client"));
  app.setOrganizationName(QStringLiteral("internal"));

  for (int i = 1; i < argc; ++i) {
    const QString arg = QString::fromLocal8Bit(argv[i]);
    if (arg == QStringLiteral("--self-test")) {
      return 0;
    }
  }

  gmssh::MainWindow window;
  window.showMaximized();

  return app.exec();
}
