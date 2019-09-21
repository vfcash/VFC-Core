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
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
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
    QPushButton *vote;
    QDoubleSpinBox *setdiff;
    QLabel *label_12;
    QWidget *tab_8;
    QGroupBox *groupBox_4;
    QLineEdit *topub;
    QLabel *label_10;
    QLabel *label_11;
    QDoubleSpinBox *send_amount;
    QPushButton *pushButton_13;
    QPushButton *newkey;
    QLineEdit *frompriv;
    QLabel *label_13;
    QLabel *label;
    QLabel *frank;
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
    QWidget *tab_6;
    QLineEdit *agent;
    QListWidget *peers_list;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->setEnabled(true);
        MainWindow->resize(562, 601);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/new/prefix1/favicon"), QSize(), QIcon::Normal, QIcon::Off);
        MainWindow->setWindowIcon(icon);
        MainWindow->setDocumentMode(false);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        tabWidget = new QTabWidget(centralwidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setGeometry(QRect(0, 0, 561, 601));
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        update_node_version = new QPushButton(tab);
        update_node_version->setObjectName(QString::fromUtf8("update_node_version"));
        update_node_version->setGeometry(QRect(360, 40, 181, 25));
        master_resync = new QPushButton(tab);
        master_resync->setObjectName(QString::fromUtf8("master_resync"));
        master_resync->setGeometry(QRect(360, 100, 181, 25));
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
        peers_sync->setGeometry(QRect(360, 70, 181, 25));
        vote = new QPushButton(tab);
        vote->setObjectName(QString::fromUtf8("vote"));
        vote->setGeometry(QRect(440, 160, 101, 25));
        setdiff = new QDoubleSpinBox(tab);
        setdiff->setObjectName(QString::fromUtf8("setdiff"));
        setdiff->setGeometry(QRect(360, 160, 71, 26));
        setdiff->setDecimals(3);
        setdiff->setMinimum(0.031000000000000);
        setdiff->setMaximum(0.240000000000000);
        setdiff->setSingleStep(0.001000000000000);
        label_12 = new QLabel(tab);
        label_12->setObjectName(QString::fromUtf8("label_12"));
        label_12->setGeometry(QRect(360, 140, 161, 17));
        tabWidget->addTab(tab, QString());
        tab_8 = new QWidget();
        tab_8->setObjectName(QString::fromUtf8("tab_8"));
        groupBox_4 = new QGroupBox(tab_8);
        groupBox_4->setObjectName(QString::fromUtf8("groupBox_4"));
        groupBox_4->setGeometry(QRect(10, 10, 541, 181));
        topub = new QLineEdit(groupBox_4);
        topub->setObjectName(QString::fromUtf8("topub"));
        topub->setGeometry(QRect(10, 50, 331, 25));
        label_10 = new QLabel(groupBox_4);
        label_10->setObjectName(QString::fromUtf8("label_10"));
        label_10->setGeometry(QRect(10, 30, 231, 17));
        label_11 = new QLabel(groupBox_4);
        label_11->setObjectName(QString::fromUtf8("label_11"));
        label_11->setGeometry(QRect(350, 80, 101, 17));
        send_amount = new QDoubleSpinBox(groupBox_4);
        send_amount->setObjectName(QString::fromUtf8("send_amount"));
        send_amount->setGeometry(QRect(350, 100, 121, 26));
        send_amount->setDecimals(3);
        send_amount->setMinimum(0.001000000000000);
        send_amount->setMaximum(4294967.294999999925494);
        send_amount->setSingleStep(0.001000000000000);
        pushButton_13 = new QPushButton(groupBox_4);
        pushButton_13->setObjectName(QString::fromUtf8("pushButton_13"));
        pushButton_13->setGeometry(QRect(480, 100, 51, 25));
        newkey = new QPushButton(groupBox_4);
        newkey->setObjectName(QString::fromUtf8("newkey"));
        newkey->setGeometry(QRect(10, 140, 251, 25));
        frompriv = new QLineEdit(groupBox_4);
        frompriv->setObjectName(QString::fromUtf8("frompriv"));
        frompriv->setGeometry(QRect(10, 100, 331, 25));
        label_13 = new QLabel(groupBox_4);
        label_13->setObjectName(QString::fromUtf8("label_13"));
        label_13->setGeometry(QRect(10, 80, 231, 17));
        label = new QLabel(groupBox_4);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(280, 140, 211, 17));
        frank = new QLabel(tab_8);
        frank->setObjectName(QString::fromUtf8("frank"));
        frank->setGeometry(QRect(100, 210, 351, 321));
        tabWidget->addTab(tab_8, QString());
        tab_7 = new QWidget();
        tab_7->setObjectName(QString::fromUtf8("tab_7"));
        explore_address = new QLineEdit(tab_7);
        explore_address->setObjectName(QString::fromUtf8("explore_address"));
        explore_address->setGeometry(QRect(0, 0, 401, 25));
        explore_combo = new QComboBox(tab_7);
        explore_combo->setObjectName(QString::fromUtf8("explore_combo"));
        explore_combo->setGeometry(QRect(400, 0, 161, 25));
        explore_list = new QListWidget(tab_7);
        explore_list->setObjectName(QString::fromUtf8("explore_list"));
        explore_list->setGeometry(QRect(0, 20, 561, 551));
        explore_list->setAutoScroll(false);
        explore_list->setDragEnabled(false);
        explore_list->setProperty("isWrapping", QVariant(false));
        tabWidget->addTab(tab_7, QString());
        tab_5 = new QWidget();
        tab_5->setObjectName(QString::fromUtf8("tab_5"));
        start_miner = new QPushButton(tab_5);
        start_miner->setObjectName(QString::fromUtf8("start_miner"));
        start_miner->setGeometry(QRect(0, 540, 101, 25));
        mine_threads = new QSpinBox(tab_5);
        mine_threads->setObjectName(QString::fromUtf8("mine_threads"));
        mine_threads->setGeometry(QRect(100, 540, 51, 26));
        mine_threads->setMinimum(1);
        mine_threads->setMaximum(256);
        list_unclaimed = new QPushButton(tab_5);
        list_unclaimed->setObjectName(QString::fromUtf8("list_unclaimed"));
        list_unclaimed->setGeometry(QRect(200, 540, 161, 25));
        claim_unclaimed = new QPushButton(tab_5);
        claim_unclaimed->setObjectName(QString::fromUtf8("claim_unclaimed"));
        claim_unclaimed->setGeometry(QRect(380, 540, 161, 25));
        mined_list = new QListWidget(tab_5);
        mined_list->setObjectName(QString::fromUtf8("mined_list"));
        mined_list->setGeometry(QRect(0, 0, 561, 541));
        tabWidget->addTab(tab_5, QString());
        tab_6 = new QWidget();
        tab_6->setObjectName(QString::fromUtf8("tab_6"));
        agent = new QLineEdit(tab_6);
        agent->setObjectName(QString::fromUtf8("agent"));
        agent->setGeometry(QRect(0, 550, 561, 25));
        agent->setReadOnly(true);
        peers_list = new QListWidget(tab_6);
        peers_list->setObjectName(QString::fromUtf8("peers_list"));
        peers_list->setGeometry(QRect(0, 0, 561, 551));
        peers_list->setAutoScroll(false);
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
        vote->setText(QCoreApplication::translate("MainWindow", "Vote", nullptr));
        label_12->setText(QCoreApplication::translate("MainWindow", "Minting Difficulty Vote:", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab), QCoreApplication::translate("MainWindow", "General", nullptr));
        groupBox_4->setTitle(QCoreApplication::translate("MainWindow", "Send Transaction", nullptr));
        label_10->setText(QCoreApplication::translate("MainWindow", "To Address:", nullptr));
        label_11->setText(QCoreApplication::translate("MainWindow", "Amount:", nullptr));
        pushButton_13->setText(QCoreApplication::translate("MainWindow", "Send", nullptr));
        newkey->setText(QCoreApplication::translate("MainWindow", "Generate New Address / Key Pair", nullptr));
        frompriv->setText(QString());
        label_13->setText(QCoreApplication::translate("MainWindow", "From Private Key:", nullptr));
        label->setText(QCoreApplication::translate("MainWindow", "Saves to `generated_keys.txt`", nullptr));
        frank->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(tab_8), QCoreApplication::translate("MainWindow", "Wallet", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_7), QCoreApplication::translate("MainWindow", "Explore", nullptr));
        start_miner->setText(QCoreApplication::translate("MainWindow", "Start Mining", nullptr));
        list_unclaimed->setText(QCoreApplication::translate("MainWindow", "List Unclaimed", nullptr));
        claim_unclaimed->setText(QCoreApplication::translate("MainWindow", "Claim Unclaimed", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_5), QCoreApplication::translate("MainWindow", "Miner", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_6), QCoreApplication::translate("MainWindow", "Peers", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
