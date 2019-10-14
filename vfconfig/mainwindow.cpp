#include <QProcess>
#include <QLocale>
#include <QDir>
#include <QUrl>
#include <QThread>
#include <QTextStream>
#include <QMessageBox>
#include <QDesktopServices>

#include "mainwindow.h"
#include "ui_mainwindow.h"

void MainWindow::saveConfig()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if (file.open(QIODevice::WriteOnly))
    {
        QTextStream stream(&file);
        stream << ui->config_edit->toPlainText() << endl;
    }
}

void MainWindow::loadConfig()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if(file.open(QIODevice::ReadOnly))
    {
        QTextStream in(&file);
        ui->config_edit->setText(in.readAll());
        file.close();
    }
}

QString int_format(int i)
{
    return QLocale(QLocale::English).toString(i);
}

QString double_format(double d)
{
    return QLocale(QLocale::English).toString(d, 'f', 3);
}

QString MainWindow::execCommand(QString cmd)
{
    QProcess process;
    process.start(cmd);
    process.waitForFinished(-1);
    return process.readAllStandardOutput();
}

void MainWindow::addPeer(const int i, QString ip, QString relayed, QString ping, QString heigh, QString version, QString cpu, QString machine, QString diff)
{
    ui->peers_table->setItem(i, 0, new QTableWidgetItem(ip));
    ui->peers_table->setItem(i, 1, new QTableWidgetItem(relayed));
    ui->peers_table->setItem(i, 2, new QTableWidgetItem(ping));
    ui->peers_table->setItem(i, 3, new QTableWidgetItem(heigh));
    ui->peers_table->setItem(i, 4, new QTableWidgetItem(version));
    ui->peers_table->setItem(i, 5, new QTableWidgetItem(cpu));
    ui->peers_table->setItem(i, 6, new QTableWidgetItem(machine));
    ui->peers_table->setItem(i, 7, new QTableWidgetItem(diff));
}

void MainWindow::updateStats(const int full)
{
    QPixmap pm(":/new/prefix1/frank.png");
    ui->frank->setPixmap(pm);
    ui->frank->setScaledContents(true);

    QString r;

    r = execCommand("vfc heigh");
    ui->total_transactions->setText("Total Transactions:        " + int_format(r.split(" / ")[1].split(" ")[0].toInt()));
    ui->blockchain_size->setText("Blockchain Size:              " + int_format(r.split(" ")[0].toInt() / 1000) + " mb");

    r = execCommand("vfc difficulty");
    ui->difficulty->setText("Difficulty:                         " + r.split("Network Difficulty: ")[1]);

    if(full == 1)
    {
        r = execCommand("vfc circulating");
        ui->circulating->setText("Circulating Supply:       " + double_format(r.toDouble()));
        r = execCommand("vfc minted");
        ui->minted->setText("Minted Supply:               " + double_format(r.toDouble()));
    }

    r = execCommand("vfc reward");
    ui->rewards->setText("Reward:                            " + r.split("Final Balance: ")[1]);
    ui->rbal->setText("Your Balance: " + r.split("Final Balance: ")[1]);

    r = execCommand("vfc version");
    ui->node_version->setText("Node Version:                 " + r);

    QFile file(QDir::homePath() + "/.vfc/public.key");
    if(file.open(QIODevice::ReadOnly))
    {
        QTextStream in(&file);
        QString rs = in.readAll();
        ui->rewards_address->setText(rs);
        ui->explore_address->setText(rs);
        file.close();
    }

    QFile file3(QDir::homePath() + "/.vfc/minted.priv");
    if(file3.open(QIODevice::ReadOnly))
    {
        QTextStream in(&file3);

        ui->mined_list->clear();
        while(!in.atEnd())
            ui->mined_list->addItem(in.readLine());

        file3.close();
    }

    //Configure the peers table
    ui->peers_table->clear();
    ui->peers_table->setRowCount(3072);
    ui->peers_table->setColumnCount(8);
    ui->peers_table->setColumnWidth(0, 160);
    ui->peers_table->setColumnWidth(1, 100);
    ui->peers_table->setColumnWidth(2, 80);
    ui->peers_table->setColumnWidth(3, 120);
    ui->peers_table->setColumnWidth(4, 80);
    ui->peers_table->setColumnWidth(5, 60);
    ui->peers_table->setColumnWidth(6, 100);
    ui->peers_table->setColumnWidth(7, 60);
    ui->peers_table->setHorizontalHeaderItem(0, new QTableWidgetItem("IPv4"));
    ui->peers_table->setHorizontalHeaderItem(1, new QTableWidgetItem("RX"));
    ui->peers_table->setHorizontalHeaderItem(2, new QTableWidgetItem("Ping"));
    ui->peers_table->setHorizontalHeaderItem(3, new QTableWidgetItem("Heigh"));
    ui->peers_table->setHorizontalHeaderItem(4, new QTableWidgetItem("Version"));
    ui->peers_table->setHorizontalHeaderItem(5, new QTableWidgetItem("CPU"));
    ui->peers_table->setHorizontalHeaderItem(6, new QTableWidgetItem("Machine"));
    ui->peers_table->setHorizontalHeaderItem(7, new QTableWidgetItem("Diff"));
    ui->peers_table->verticalHeader()->setVisible(0);
    ui->peers_table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    r = execCommand("vfc peers");
    QStringList pl = r.split("\n");
    int pi = 0;
    foreach(QString v, pl)
    {
        if(v[0].isDigit())
        {
            QStringList p1 = v.split(" / ");
            if(p1.count() >= 4)
            {
                QStringList p2 = p1[3].split(", ");
                if(p2.count() >= 5)
                {
                    addPeer(pi, p1[0], p1[1], p1[2], p2[0], p2[1], p2[2], p2[3], p2[4]);
                    pi++;
                }
                else
                {
                    addPeer(pi, p1[0], p1[1], p1[2], "0", "0", "0", "0", "0");
                    pi++;
                }
            }
            else if(p1.count() == 3)
            {
                addPeer(pi, p1[0], p1[1], p1[2], "0", "0", "0", "0", "0");
                pi++;
            }
        }

        if(v[0] == 'A' && v[1] == 'l')
        {
            ui->num_peers->setText("Num Peers:                      " + v.split(": ")[1] + " / 3072");
            ui->peers_table->setRowCount(v.split(": ")[1].toInt());
        }
    }

}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->statusbar->hide();

    QStringList list = (QStringList()<<"All"<<"Received"<<"Sent");
    ui->explore_combo->addItems(list);

    timerId = startTimer(9000);
    timerId2 = startTimer(680000);

    updateStats(1);
    loadConfig();
}

MainWindow::~MainWindow()
{
    killTimer(timerId);
    killTimer(timerId2);
    delete ui;
}

void MainWindow::timerEvent(QTimerEvent *event)
{
    if(event->timerId() == timerId)
        updateStats(0);
   else if(event->timerId() == timerId2)
        updateStats(1);
}

void MainWindow::on_update_node_version_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc update; bash\"");
}

void MainWindow::on_peers_sync_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc sync\"");
}

void MainWindow::on_master_resync_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc master_resync; bash\"");
}

void MainWindow::on_save_config_clicked()
{
    saveConfig();
}

void MainWindow::on_load_config_clicked()
{
    loadConfig();
}

void MainWindow::on_single_config_clicked()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if (file.open(QIODevice::WriteOnly))
    {
        QTextStream stream(&file);
        stream << "multi-threaded 0\nreplay-threads 8\nreplay-delay 1000\n";
    }
    loadConfig();
}

void MainWindow::on_multi_config_clicked()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if (file.open(QIODevice::WriteOnly))
    {
        QTextStream stream(&file);
        stream << "multi-threaded 1\nreplay-threads 32\nreplay-delay 1000\n";
    }
    loadConfig();
}

void MainWindow::on_minimal_config_clicked()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if (file.open(QIODevice::WriteOnly))
    {
        QTextStream stream(&file);
        stream << "multi-threaded 0\nreplay-threads 3\nreplay-delay 10000\n";
    }
    loadConfig();
}

void MainWindow::on_start_miner_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc mine " + QString::number(ui->mine_threads->value()) + "\"");
}

void MainWindow::on_list_unclaimed_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc unclaimed; bash\"");
}

void MainWindow::on_claim_unclaimed_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc claim\"");
}

void MainWindow::on_explore_combo_currentIndexChanged(int index)
{
    if(ui->explore_address->text() == "")
        return;

    ui->explore_list->clear();

    QString t;
    if(index == 0)
        t = "all";
    if(index == 1)
        t = "in";
    if(index == 2)
        t = "out";
    QString r = execCommand("vfc " + t + " " + ui->explore_address->text());
    QStringList pl = r.split("\n");
    foreach(QString v, pl)
        ui->explore_list->addItem(v);
}

void MainWindow::on_newkey_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc new 2>&1 | tee -a .vfc/generated_keys.txt; bash\"");
}

void MainWindow::on_start_node_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc; bash\"");
}

void MainWindow::on_send_trans_clicked()
{
    if(ui->topub->text() == "" || ui->frompriv->text() == "")
    {
        QMessageBox msgBox;
        msgBox.setText("Please complete the inputs.");
        msgBox.exec();
        return;
    }

    QString frompub = execCommand("vfc getpub " + ui->frompriv->text()).split("Public: ")[1].replace("\n", "");

    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc " + frompub + " " + ui->topub->text() + " " + QString::number(ui->send_amount->value()) + " " + ui->frompriv->text() + "; bash\"");
}

void MainWindow::on_vgate_clicked()
{
    QDesktopServices::openUrl(QUrl("https://x.vite.net/trade?symbol=VFC-000_BTC-000&category=BTC"));
}

void MainWindow::on_bihodl_clicked()
{
    QDesktopServices::openUrl(QUrl("https://bihodl.com/#/exchange/vfc_usdt"));
}

void MainWindow::on_vfhome_clicked()
{
    QDesktopServices::openUrl(QUrl("https://vfcash.uk"));
}

void MainWindow::on_telegram_clicked()
{
    QDesktopServices::openUrl(QUrl("https://t.me/vfcash"));
}

void MainWindow::on_discord_clicked()
{
    QDesktopServices::openUrl(QUrl("https://discord.gg/VFa4A5v"));
}

void MainWindow::on_open_minted_clicked()
{
    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"xdg-open ~/.vfc/minted.priv; bash\"");
}

void MainWindow::on_qsend_clicked()
{
    if(ui->qtopub->text() == "")
    {
        QMessageBox msgBox;
        msgBox.setText("Please input to address.");
        msgBox.exec();
        return;
    }

    QProcess *qp = new QProcess;
    qp->startDetached("xterm -e \"vfc qsend " + QString::number(ui->send_amount->value()) + " " + ui->qtopub->text() + "; bash\"");
}
