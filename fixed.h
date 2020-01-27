#ifndef FIXED_H
#define FIXED_H

// For compile time, is this going to be a client (0) or a web-service masternode (1)?
#define MASTER_NODE 0

// Run as root or not, recommended to run as root if your using this as a local service, for personal use, run as user (0)
#define RUN_AS_ROOT 0

// How many v the currency inflates by on each transaction
#define INFLATION_TAX 3000

// Easiest minting difficulty.
#define MIN_DIFFICULTY 0.180

#endif
