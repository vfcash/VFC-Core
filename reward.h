#ifndef REWARD_H
#define REWARD_H

// For compile time, is this going to be a client or a reward-paying masternode?
#define MASTER_NODE 0 //your not the master of this network !!

// How often to pay rewards qRand(540, 660)
#define REWARD_INTERVAL qRand(540, 660)

// How often to ping the peer requesting a reward address during their reward interval period
#define REWARD_RETRY_INTERVAL 60

// Reward Command
const char reward_command[]="coin dDWmPjoUtMyvL7gtQwJxpFcE1VHCdY1ahVZpcFCSUfuK%s %u privatekey_removed > /dev/null";

#endif
