#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    void timerEvent(QTimerEvent *event);
    int timerId;
    int timerId2;

protected:
    Ui::MainWindow *ui;

    QString execCommand(QString cmd);
    void updateStats(const int full);
    void saveConfig();
    void loadConfig();

private slots:
    void on_update_node_version_clicked();
    void on_peers_sync_clicked();
    void on_master_resync_clicked();
    void on_vote_clicked();
    void on_save_config_clicked();
    void on_load_config_clicked();
    void on_single_config_clicked();
    void on_multi_config_clicked();
    void on_minimal_config_clicked();
    void on_start_miner_clicked();
    void on_list_unclaimed_clicked();
    void on_claim_unclaimed_clicked();
    void on_explore_combo_currentIndexChanged(int index);
    void on_newkey_clicked();
    void on_send_trans_clicked();
    void on_start_node_clicked();
};
#endif // MAINWINDOW_H
