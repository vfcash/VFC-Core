#ifndef REWARD_H
#define REWARD_H

// For compile time, is this going to be a client or a reward-paying masternode?
#define MASTER_NODE 0

//Run as root or not, recommended to run as root if your using this as a local service, for personal use, run as user (0)
#define RUN_AS_ROOT 0

//How many v the currency inflates by on each transaction
#define INFLATION_TAX 3000

#endif
