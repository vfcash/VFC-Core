#include <QProcess>
#include <QLocale>
#include <QDir>
#include <QThread>
#include <QTextStream>
#include <QMessageBox>

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

    r = execCommand("vfc version");
    ui->node_version->setText("Node Version:                 " + r);

    r = execCommand("vfc agent");
    ui->agent->setText("Your User-Agent: " + r);
    QStringList sl = r.split(", ");
    if(sl.length() > 4)
        ui->setdiff->setValue(sl[4].toDouble());

    r = execCommand("vfc peers");
    QStringList pl = r.split("\n");
    ui->peers_list->clear();
    foreach(QString v, pl)
    {
        if(v[0].isDigit())
            ui->peers_list->addItem(v);

        if(v[0] == 'A' && v[1] == 'l')
            ui->num_peers->setText("Num Peers:                      " + v.split(": ")[1] + " / 3072");
    }

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

        while(!in.atEnd())
            ui->mined_list->addItem(in.readLine());

        file3.close();
    }

    loadConfig();

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
    timerId2 = startTimer(180000);

    updateStats(1);
}

MainWindow::~MainWindow()
{
    killTimer(timerId);
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

void MainWindow::on_vote_clicked()
{
    QString r = execCommand("vfc setdiff " + QString::number(ui->setdiff->value()) );
    QMessageBox msgBox;
    msgBox.setText("Your difficulty vote has been updated to " + QString::number(ui->setdiff->value()));
    msgBox.exec();
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
        stream << "multi-threaded 0\nmmap 1\nreplay-delay 1000\n";
    }
    loadConfig();
}

void MainWindow::on_multi_config_clicked()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if (file.open(QIODevice::WriteOnly))
    {
        QTextStream stream(&file);
        stream << "multi-threaded 1\nmmap 1\nreplay-delay 1000\n";
    }
    loadConfig();
}

void MainWindow::on_minimal_config_clicked()
{
    QFile file(QDir::homePath() + "/.vfc/vfc.cnf");
    if (file.open(QIODevice::WriteOnly))
    {
        QTextStream stream(&file);
        stream << "multi-threaded 0\nmmap 0\nreplay-delay 10000\n";
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
    qp->startDetached("xterm -e \"vfc unclaimed\"");
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
    ui->peers_list->clear();
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
