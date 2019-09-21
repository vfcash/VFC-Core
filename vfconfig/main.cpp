#include "mainwindow.h"

#include <QApplication>
#include <QDesktopWidget>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    QRect screenGeometry = QApplication::desktop()->screenGeometry();
    w.move((screenGeometry.width()-w.width()) / 2, (screenGeometry.height()-w.height()) / 2);
    w.show();
    w.setFixedSize(w.size());
    return a.exec();
}


