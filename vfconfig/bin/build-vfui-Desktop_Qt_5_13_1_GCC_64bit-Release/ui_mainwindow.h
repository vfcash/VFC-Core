/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.13.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QTabWidget *tabWidget;
    QWidget *tab;
    QPushButton *update_node_version;
    QPushButton *master_resync;
    QGroupBox *groupBox;
    QTextEdit *config_edit;
    QGroupBox *groupBox_2;
    QLabel *total_transactions;
    QLabel *blockchain_size;
    QLabel *num_peers;
    QLabel *difficulty;
    QLabel *rewards;
    QLabel *circulating;
    QLabel *minted;
    QLabel *node_version;
    QGroupBox *groupBox_3;
    QLineEdit *rewards_address;
    QPushButton *save_config;
    QPushButton *single_config;
    QPushButton *multi_config;
    QPushButton *minimal_config;
    QPushButton *load_config;
    QLabel *label_9;
    QPushButton *peers_sync;
    QPushButton *start_node;
    QFrame *line;
    QPushButton *vgate;
    QPushButton *bihodl;
    QPushButton *vfhome;
    QPushButton *discord;
    QPushButton *telegram;
    QWidget *tab_8;
    QGroupBox *groupBox_4;
    QLineEdit *topub;
    QLabel *label_10;
    QLabel *label_11;
    QDoubleSpinBox *send_amount;
    QPushButton *send_trans;
    QLineEdit *frompriv;
    QLabel *label_13;
    QLabel *frank;
    QPushButton *newkey;
    QGroupBox *groupBox_5;
    QLineEdit *qtopub;
    QLabel *label_14;
    QLabel *label_15;
    QDoubleSpinBox *qamount;
    QPushButton *qsend;
    QLabel *rbal;
    QWidget *tab_7;
    QLineEdit *explore_address;
    QComboBox *explore_combo;
    QListWidget *explore_list;
    QWidget *tab_5;
    QPushButton *start_miner;
    QSpinBox *mine_threads;
    QPushButton *list_unclaimed;
    QPushButton *claim_unclaimed;
    QListWidget *mined_list;
    QPushButton *open_minted;
    QWidget *tab_6;
    QLineEdit *agent;
    QTableWidget *peers_table;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->setEnabled(true);
        MainWindow->resize(782, 601);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/new/prefix1/favicon"), QSize(), QIcon::Normal, QIcon::Off);
        MainWindow->setWindowIcon(icon);
        MainWindow->setDocumentMode(false);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        tabWidget = new QTabWidget(centralwidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setGeometry(QRect(0, 0, 781, 601));
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        update_node_version = new QPushButton(tab);
        update_node_version->setObjectName(QString::fromUtf8("update_node_version"));
        update_node_version->setGeometry(QRect(360, 30, 181, 25));
        master_resync = new QPushButton(tab);
        master_resync->setObjectName(QString::fromUtf8("master_resync"));
        master_resync->setGeometry(QRect(360, 90, 181, 25));
        groupBox = new QGroupBox(tab);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        groupBox->setGeometry(QRect(10, 290, 331, 271));
        config_edit = new QTextEdit(groupBox);
        config_edit->setObjectName(QString::fromUtf8("config_edit"));
        config_edit->setGeometry(QRect(10, 30, 311, 231));
        groupBox_2 = new QGroupBox(tab);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        groupBox_2->setGeometry(QRect(10, 10, 331, 201));
        total_transactions = new QLabel(groupBox_2);
        total_transactions->setObjectName(QString::fromUtf8("total_transactions"));
        total_transactions->setGeometry(QRect(10, 30, 311, 17));
        blockchain_size = new QLabel(groupBox_2);
        blockchain_size->setObjectName(QString::fromUtf8("blockchain_size"));
        blockchain_size->setGeometry(QRect(10, 50, 311, 17));
        num_peers = new QLabel(groupBox_2);
        num_peers->setObjectName(QString::fromUtf8("num_peers"));
        num_peers->setGeometry(QRect(10, 70, 311, 17));
        difficulty = new QLabel(groupBox_2);
        difficulty->setObjectName(QString::fromUtf8("difficulty"));
        difficulty->setGeometry(QRect(10, 90, 311, 17));
        rewards = new QLabel(groupBox_2);
        rewards->setObjectName(QString::fromUtf8("rewards"));
        rewards->setGeometry(QRect(10, 150, 311, 17));
        circulating = new QLabel(groupBox_2);
        circulating->setObjectName(QString::fromUtf8("circulating"));
        circulating->setGeometry(QRect(10, 110, 311, 17));
        minted = new QLabel(groupBox_2);
        minted->setObjectName(QString::fromUtf8("minted"));
        minted->setGeometry(QRect(10, 130, 311, 17));
        node_version = new QLabel(groupBox_2);
        node_version->setObjectName(QString::fromUtf8("node_version"));
        node_version->setGeometry(QRect(10, 170, 311, 17));
        groupBox_3 = new QGroupBox(tab);
        groupBox_3->setObjectName(QString::fromUtf8("groupBox_3"));
        groupBox_3->setGeometry(QRect(10, 220, 541, 61));
        rewards_address = new QLineEdit(groupBox_3);
        rewards_address->setObjectName(QString::fromUtf8("rewards_address"));
        rewards_address->setGeometry(QRect(10, 30, 521, 25));
        rewards_address->setDragEnabled(true);
        rewards_address->setReadOnly(true);
        save_config = new QPushButton(tab);
        save_config->setObjectName(QString::fromUtf8("save_config"));
        save_config->setGeometry(QRect(360, 320, 181, 25));
        single_config = new QPushButton(tab);
        single_config->setObjectName(QString::fromUtf8("single_config"));
        single_config->setGeometry(QRect(360, 410, 181, 25));
        multi_config = new QPushButton(tab);
        multi_config->setObjectName(QString::fromUtf8("multi_config"));
        multi_config->setGeometry(QRect(360, 440, 181, 25));
        minimal_config = new QPushButton(tab);
        minimal_config->setObjectName(QString::fromUtf8("minimal_config"));
        minimal_config->setGeometry(QRect(360, 470, 181, 25));
        load_config = new QPushButton(tab);
        load_config->setObjectName(QString::fromUtf8("load_config"));
        load_config->setGeometry(QRect(360, 350, 181, 25));
        label_9 = new QLabel(tab);
        label_9->setObjectName(QString::fromUtf8("label_9"));
        label_9->setGeometry(QRect(360, 390, 171, 17));
        peers_sync = new QPushButton(tab);
        peers_sync->setObjectName(QString::fromUtf8("peers_sync"));
        peers_sync->setGeometry(QRect(360, 60, 181, 25));
        start_node = new QPushButton(tab);
        start_node->setObjectName(QString::fromUtf8("start_node"));
        start_node->setGeometry(QRect(360, 120, 181, 25));
        QFont font;
        font.setBold(true);
        font.setWeight(75);
        start_node->setFont(font);
        line = new QFrame(tab);
        line->setObjectName(QString::fromUtf8("line"));
        line->setGeometry(QRect(550, 30, 20, 521));
        line->setFrameShape(QFrame::VLine);
        line->setFrameShadow(QFrame::Sunken);
        vgate = new QPushButton(tab);
        vgate->setObjectName(QString::fromUtf8("vgate"));
        vgate->setGeometry(QRect(580, 80, 181, 25));
        bihodl = new QPushButton(tab);
        bihodl->setObjectName(QString::fromUtf8("bihodl"));
        bihodl->setGeometry(QRect(580, 110, 181, 25));
        vfhome = new QPushButton(tab);
        vfhome->setObjectName(QString::fromUtf8("vfhome"));
        vfhome->setGeometry(QRect(580, 30, 181, 25));
        discord = new QPushButton(tab);
        discord->setObjectName(QString::fromUtf8("discord"));
        discord->setGeometry(QRect(580, 190, 181, 25));
        telegram = new QPushButton(tab);
        telegram->setObjectName(QString::fromUtf8("telegram"));
        telegram->setGeometry(QRect(580, 160, 181, 25));
        tabWidget->addTab(tab, QString());
        tab_8 = new QWidget();
        tab_8->setObjectName(QString::fromUtf8("tab_8"));
        groupBox_4 = new QGroupBox(tab_8);
        groupBox_4->setObjectName(QString::fromUtf8("groupBox_4"));
        groupBox_4->setGeometry(QRect(50, 10, 671, 161));
        topub = new QLineEdit(groupBox_4);
        topub->setObjectName(QString::fromUtf8("topub"));
        topub->setGeometry(QRect(20, 110, 441, 31));
        label_10 = new QLabel(groupBox_4);
        label_10->setObjectName(QString::fromUtf8("label_10"));
        label_10->setGeometry(QRect(20, 90, 221, 20));
        label_11 = new QLabel(groupBox_4);
        label_11->setObjectName(QString::fromUtf8("label_11"));
        label_11->setGeometry(QRect(470, 90, 101, 17));
        send_amount = new QDoubleSpinBox(groupBox_4);
        send_amount->setObjectName(QString::fromUtf8("send_amount"));
        send_amount->setGeometry(QRect(470, 110, 121, 31));
        send_amount->setDecimals(3);
        send_amount->setMinimum(0.001000000000000);
        send_amount->setMaximum(4294967.294999999925494);
        send_amount->setSingleStep(0.001000000000000);
        send_trans = new QPushButton(groupBox_4);
        send_trans->setObjectName(QString::fromUtf8("send_trans"));
        send_trans->setGeometry(QRect(600, 110, 51, 31));
        send_trans->setFont(font);
        frompriv = new QLineEdit(groupBox_4);
        frompriv->setObjectName(QString::fromUtf8("frompriv"));
        frompriv->setGeometry(QRect(20, 50, 631, 31));
        label_13 = new QLabel(groupBox_4);
        label_13->setObjectName(QString::fromUtf8("label_13"));
        label_13->setGeometry(QRect(20, 30, 221, 20));
        frank = new QLabel(tab_8);
        frank->setObjectName(QString::fromUtf8("frank"));
        frank->setGeometry(QRect(460, 320, 261, 231));
        newkey = new QPushButton(tab_8);
        newkey->setObjectName(QString::fromUtf8("newkey"));
        newkey->setGeometry(QRect(50, 320, 251, 31));
        QFont font1;
        font1.setBold(false);
        font1.setWeight(50);
        newkey->setFont(font1);
        groupBox_5 = new QGroupBox(tab_8);
        groupBox_5->setObjectName(QString::fromUtf8("groupBox_5"));
        groupBox_5->setGeometry(QRect(50, 180, 671, 121));
        qtopub = new QLineEdit(groupBox_5);
        qtopub->setObjectName(QString::fromUtf8("qtopub"));
        qtopub->setGeometry(QRect(20, 50, 441, 31));
        label_14 = new QLabel(groupBox_5);
        label_14->setObjectName(QString::fromUtf8("label_14"));
        label_14->setGeometry(QRect(20, 30, 221, 20));
        label_15 = new QLabel(groupBox_5);
        label_15->setObjectName(QString::fromUtf8("label_15"));
        label_15->setGeometry(QRect(470, 30, 101, 17));
        qamount = new QDoubleSpinBox(groupBox_5);
        qamount->setObjectName(QString::fromUtf8("qamount"));
        qamount->setGeometry(QRect(470, 50, 121, 31));
        qamount->setDecimals(3);
        qamount->setMinimum(0.001000000000000);
        qamount->setMaximum(4294967.294999999925494);
        qamount->setSingleStep(0.001000000000000);
        qsend = new QPushButton(groupBox_5);
        qsend->setObjectName(QString::fromUtf8("qsend"));
        qsend->setGeometry(QRect(600, 50, 51, 31));
        qsend->setFont(font);
        rbal = new QLabel(groupBox_5);
        rbal->setObjectName(QString::fromUtf8("rbal"));
        rbal->setGeometry(QRect(20, 90, 441, 17));
        tabWidget->addTab(tab_8, QString());
        tab_7 = new QWidget();
        tab_7->setObjectName(QString::fromUtf8("tab_7"));
        explore_address = new QLineEdit(tab_7);
        explore_address->setObjectName(QString::fromUtf8("explore_address"));
        explore_address->setGeometry(QRect(0, 0, 601, 31));
        explore_combo = new QComboBox(tab_7);
        explore_combo->setObjectName(QString::fromUtf8("explore_combo"));
        explore_combo->setGeometry(QRect(600, 0, 181, 31));
        explore_list = new QListWidget(tab_7);
        explore_list->setObjectName(QString::fromUtf8("explore_list"));
        explore_list->setEnabled(true);
        explore_list->setGeometry(QRect(0, 30, 781, 541));
        explore_list->setAutoScroll(false);
        explore_list->setDragEnabled(false);
        explore_list->setProperty("isWrapping", QVariant(false));
        tabWidget->addTab(tab_7, QString());
        tab_5 = new QWidget();
        tab_5->setObjectName(QString::fromUtf8("tab_5"));
        start_miner = new QPushButton(tab_5);
        start_miner->setObjectName(QString::fromUtf8("start_miner"));
        start_miner->setGeometry(QRect(40, 540, 101, 25));
        start_miner->setFont(font1);
        mine_threads = new QSpinBox(tab_5);
        mine_threads->setObjectName(QString::fromUtf8("mine_threads"));
        mine_threads->setGeometry(QRect(140, 540, 61, 26));
        mine_threads->setMinimum(1);
        mine_threads->setMaximum(256);
        list_unclaimed = new QPushButton(tab_5);
        list_unclaimed->setObjectName(QString::fromUtf8("list_unclaimed"));
        list_unclaimed->setGeometry(QRect(390, 540, 161, 25));
        claim_unclaimed = new QPushButton(tab_5);
        claim_unclaimed->setObjectName(QString::fromUtf8("claim_unclaimed"));
        claim_unclaimed->setGeometry(QRect(570, 540, 161, 25));
        mined_list = new QListWidget(tab_5);
        mined_list->setObjectName(QString::fromUtf8("mined_list"));
        mined_list->setEnabled(true);
        mined_list->setGeometry(QRect(0, 0, 781, 541));
        open_minted = new QPushButton(tab_5);
        open_minted->setObjectName(QString::fromUtf8("open_minted"));
        open_minted->setGeometry(QRect(270, 540, 91, 25));
        tabWidget->addTab(tab_5, QString());
        open_minted->raise();
        start_miner->raise();
        mine_threads->raise();
        list_unclaimed->raise();
        claim_unclaimed->raise();
        mined_list->raise();
        tab_6 = new QWidget();
        tab_6->setObjectName(QString::fromUtf8("tab_6"));
        agent = new QLineEdit(tab_6);
        agent->setObjectName(QString::fromUtf8("agent"));
        agent->setGeometry(QRect(0, 540, 781, 31));
        agent->setFont(font);
        agent->setReadOnly(true);
        peers_table = new QTableWidget(tab_6);
        peers_table->setObjectName(QString::fromUtf8("peers_table"));
        peers_table->setEnabled(true);
        peers_table->setGeometry(QRect(0, 0, 781, 541));
        peers_table->setSortingEnabled(false);
        tabWidget->addTab(tab_6, QString());
        MainWindow->setCentralWidget(centralwidget);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "VF Cash Node / Qt", nullptr));
#if QT_CONFIG(tooltip)
        MainWindow->setToolTip(QString());
#endif // QT_CONFIG(tooltip)
        update_node_version->setText(QCoreApplication::translate("MainWindow", "Update Node Version", nullptr));
        master_resync->setText(QCoreApplication::translate("MainWindow", "Master Resync", nullptr));
        groupBox->setTitle(QCoreApplication::translate("MainWindow", "Configuration File / Editor", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("MainWindow", "Node Statistics", nullptr));
        total_transactions->setText(QCoreApplication::translate("MainWindow", "Total Transactions:", nullptr));
        blockchain_size->setText(QCoreApplication::translate("MainWindow", "Blockchain Size:", nullptr));
        num_peers->setText(QCoreApplication::translate("MainWindow", "Num Peers:", nullptr));
        difficulty->setText(QCoreApplication::translate("MainWindow", "Difficulty:", nullptr));
        rewards->setText(QCoreApplication::translate("MainWindow", "Rewards:", nullptr));
        circulating->setText(QCoreApplication::translate("MainWindow", "Circulating Supply:", nullptr));
        minted->setText(QCoreApplication::translate("MainWindow", "Minted Supply:", nullptr));
        node_version->setText(QCoreApplication::translate("MainWindow", "Node Version:", nullptr));
        groupBox_3->setTitle(QCoreApplication::translate("MainWindow", "Node Rewards Address / Public Key", nullptr));
        save_config->setText(QCoreApplication::translate("MainWindow", "Save Config", nullptr));
        single_config->setText(QCoreApplication::translate("MainWindow", "Single-Threaded Config", nullptr));
        multi_config->setText(QCoreApplication::translate("MainWindow", "Multi-Threaded Config", nullptr));
        minimal_config->setText(QCoreApplication::translate("MainWindow", "Minimal Hardware Config", nullptr));
        load_config->setText(QCoreApplication::translate("MainWindow", "Load Config", nullptr));
        label_9->setText(QCoreApplication::translate("MainWindow", "Preset Configurations:", nullptr));
        peers_sync->setText(QCoreApplication::translate("MainWindow", "Peers Sync", nullptr));
        start_node->setText(QCoreApplication::translate("MainWindow", "Start Node", nullptr));
        vgate->setText(QCoreApplication::translate("MainWindow", "VGATE Exchange", nullptr));
        bihodl->setText(QCoreApplication::translate("MainWindow", "Bihodl Exchange", nullptr));
        vfhome->setText(QCoreApplication::translate("MainWindow", "VF Cash Homepage", nullptr));
        discord->setText(QCoreApplication::translate("MainWindow", "Discord", nullptr));
        telegram->setText(QCoreApplication::translate("MainWindow", "Telegram", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab), QCoreApplication::translate("MainWindow", "General", nullptr));
        groupBox_4->setTitle(QCoreApplication::translate("MainWindow", "Send Transaction", nullptr));
        label_10->setText(QCoreApplication::translate("MainWindow", "To Address:", nullptr));
        label_11->setText(QCoreApplication::translate("MainWindow", "Amount:", nullptr));
        send_trans->setText(QCoreApplication::translate("MainWindow", "Send", nullptr));
        frompriv->setText(QString());
        label_13->setText(QCoreApplication::translate("MainWindow", "From Private Key:", nullptr));
        frank->setText(QString());
        newkey->setText(QCoreApplication::translate("MainWindow", "Generate New Address / Key Pair", nullptr));
        groupBox_5->setTitle(QCoreApplication::translate("MainWindow", "Quick Send (sends directly from your rewards address)", nullptr));
        label_14->setText(QCoreApplication::translate("MainWindow", "To Address:", nullptr));
        label_15->setText(QCoreApplication::translate("MainWindow", "Amount:", nullptr));
        qsend->setText(QCoreApplication::translate("MainWindow", "Send", nullptr));
        rbal->setText(QCoreApplication::translate("MainWindow", "Your Balance: 0 VFC", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_8), QCoreApplication::translate("MainWindow", "Wallet", nullptr));
        explore_address->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(tab_7), QCoreApplication::translate("MainWindow", "Explore", nullptr));
        start_miner->setText(QCoreApplication::translate("MainWindow", "Start Mining", nullptr));
        list_unclaimed->setText(QCoreApplication::translate("MainWindow", "List Unclaimed", nullptr));
        claim_unclaimed->setText(QCoreApplication::translate("MainWindow", "Claim Unclaimed", nullptr));
        open_minted->setText(QCoreApplication::translate("MainWindow", "Open", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_5), QCoreApplication::translate("MainWindow", "Miner", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_6), QCoreApplication::translate("MainWindow", "Peers", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
