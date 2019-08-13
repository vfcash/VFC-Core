/*
    VF Cash has been created by James William Fletcher
    http://github.com/mrbid

    A Cryptocurrency for Linux written in C.
    https://vf.cash
    https://vfcash.uk

    CRYPTO:
    - https://github.com/brainhub/SHA3IUF   [SHA3]
    - https://github.com/esxgx/easy-ecc     [ECDSA]

    Additional Dependencies:
    - CRC64.c - Salvatore Sanfilippo
    - Base58.c - Luke Dashjr

    NOTES:
    Only Supports IPv4 addresses.
    Local storage in ~/vfc

    *** In it's current state we only track peer's who send a transaction to the server. ***
    *** Send a transaction to yourself, you wont see any address balance until verified ***

    There is a small UDP transaction queue and a processing thread to make sure normal
    UDP transmissions do not get particularly blocked up.

    Peers need to be aware of each other by referal, passing the origin ip of a
    transaction across the echo chamber makes this possible, but this also exposes
    the IP address of the clients operating specific transactions. This is fine if
    you are behind a VPN but otherwise, this is generally bad for accountability.
    This could give the an attacker insights that could lead to a successfully
    poisioned block replay. Although the risks are SLIM I would suggest mixing
    this IP list up aka the ip and ipo uint32 arrays when there is more than one
    index.

    Peers can only be part of the network by proving they control VFC currency in a
    given VFC address. This is done by making a transaction from the same IP as the
    node running the full time VFC daemon. Only then will the local VFC daemon
    recieve all transactions broadcast around the VFC p2p network.

    This client will try to broadcast all transactions through the master first
    and then the peer list.

    Transactions echo two relays deep into the peers, making sure most nodes are
    repeat notified about the transactions due to the echoing of a packet around in
    a two relay deep p2p peers broadcast, making a less reliable UDP protocol
    more reliable and ensuring all peers get the transaction.

    TODO:
    - Scanning for peers could do with scanning more specific ranges that are more
      worth-while

    Distributed under the MIT software license, see the accompanying
    file COPYING or http://www.opensource.org/licenses/mit-license.php.

*/

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/sysinfo.h> //CPU cores
#include <sys/stat.h> //mkdir
#include <fcntl.h> //open
#include <time.h> //time
#include <sys/mman.h> //mmap
#include <unistd.h> //sleep
#include <sys/utsname.h> //uname
#include <locale.h> //setlocale
#include <signal.h> //SIGPIPE
#include <pthread.h> //Threading

#include "ecc.h"
#include "sha3.h"
#include "crc64.h"
#include "base58.h"

#include "reward.h"

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////

//Client Configuration
const char version[]="0.52";
const uint16_t gport = 8787;
const char master_ip[] = "68.183.49.225";

//Error Codes
#define ERROR_NOFUNDS -1
#define ERROR_SIGFAIL -2
#define ERROR_UIDEXIST -3
#define ERROR_WRITE -4

//Node Settings
#define MAX_SITES 11111101              // Maximum UID hashmap slots (11111101 = 11mb) it's a prime number, for performance, only use primes.
#define MAX_TRANS_QUEUE 4096            // Maximum transaction backlog to keep in real-time (the lower the better tbh, only benefits from a higher number during block replays)
#define MAX_REXI_SIZE 1024              // Maximum size of rExi (this should be atlest ~MAX_TRANS_QUEUE/3)
#define MAX_PEERS 3072                  // Maximum trackable peers at once (this is a high enough number)
#define MAX_PEER_EXPIRE_SECONDS 10800   // Seconds before a peer can be replaced by another peer. secs(3 days=259200, 3 hours=10800)
#define PING_INTERVAL 540               // How often top ping the peers to see if they are still alive
#define REPLAY_SIZE 6944                // How many transactions to send a peer in one replay request , 2mb 13888 / 1mb 6944
#define MAX_THREADS_BUFF 512            // Maximum threads allocated for replay, dynamic scalling cannot exceed this.

//Generic Buffer Sizes
#define RECV_BUFF_SIZE 256
#define MIN_LEN 256

//Chain Paths
#define CHAIN_FILE ".vfc/blocks.dat"
#define BADCHAIN_FILE ".vfc/bad_blocks.dat"

//Vairable Definitions
#define uint uint32_t
#define mval uint32_t
#define ulong unsigned long long int

//Operating Global Variables
#if MASTER_NODE == 1
    time_t nextreward = 0;
    uint rewardindex = 0;
    uint rewardpaid = 1;
#endif
char mid[8];                         //Clients private identification code used in pings etc.
ulong err = 0;                       //Global error count
uint replay_allow[6] = {0,0,0,0,0,0};//IP address of peer allowed to send replay blocks
uint replay_height = 0;              //Block Height of current peer authorized to receive a replay from
uint64_t balance_accumulator = 0;    //For accumulating the highest network balance of a requested address
uint nthreads = 0;                   //number of mining threads
char myrewardkey[MIN_LEN];           //client reward addr public key
char myrewardkeyp[MIN_LEN];          //client reward addr private key
uint8_t genesis_pub[ECC_CURVE+1];    //genesis address public key
uint thread_ip[MAX_THREADS_BUFF];    //IP's replayed to by threads (prevents launching a thread for the same IP more than once)
uint threads = 0;                    //number of replay threads
uint MAX_THREADS = 6;                //maximum number of replay threads
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex3 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex4 = PTHREAD_MUTEX_INITIALIZER;
uint is8664 = 1;

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Util Functions
*/

//Convert to decimal balance
double toDB(const uint64_t b)
{
    return (double)(b) / 1000;
}
mval fromDB(const double b) //and from
{
    return (mval)(b * 1000);
}

char* getHome()
{
#if RUN_AS_ROOT == 1
    static char ret[] = "/srv";
    return ret;
#else
    char *ret;
    if((ret = getenv("VFCDIR")) == NULL)
        if((ret = getenv("HOME")) == NULL)
            ret = getpwuid(getuid())->pw_dir;
    return ret;
#endif
}

uint qRand(const uint min, const uint max)
{
    static time_t ls = 0;
    if(time(0) > ls)
    {
        srand(time(0));
        ls = time(0) + 33;
    }
    return ( ((float)rand() / RAND_MAX) * (max-min) ) + min; //(rand()%(max-min))+min;
}

void timestamp()
{
    time_t ltime = time(0);
    printf("\033[1m\x1B[31m%s\x1B[0m\033[0m", asctime(localtime(&ltime)));
}

uint isalonu(char c)
{
    if(c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122)
        return 1;
    return 0;
}

double floor(double i)
{
    if(i < 0)
        return (int)i - 1;
    else
        return (int)i;
}

void forceWrite(const char* file, const void* data, const size_t data_len)
{
    FILE* f = fopen(file, "w");
    if(f)
    {
        uint fc = 0;
        while(fwrite(data, 1, data_len, f) < data_len)
        {
            fclose(f);
            fopen(file, "w");
            fc++;
            if(fc > 333)
            {
                printf("\033[1m\x1B[31mERROR: fwrite() in forceWrite() has failed for '%s'.\x1B[0m\033[0m\n", file);
                err++;
                fclose(f);
                return;
            }
            if(f == NULL)
                continue;
        }

        fclose(f);
    }
}

void forceRead(const char* file, void* data, const size_t data_len)
{
    FILE* f = fopen(file, "r");
    if(f)
    {
        uint fc = 0;
        while(fread(data, 1, data_len, f) < data_len)
        {
            fclose(f);
            fopen(file, "r");
            fc++;
            if(fc > 333)
            {
                printf("\033[1m\x1B[31mERROR: fread() in forceRead() has failed for '%s'.\x1B[0m\033[0m\n", file);
                err++;
                fclose(f);
                return;
            }
            if(f == NULL)
                continue;
        }

        fclose(f);
    }
}

void forceTruncate(const char* file, const size_t pos)
{
    int f = open(file, O_WRONLY);
    if(f)
    {
        uint c = 0;
        while(ftruncate(f, pos) == -1)
        {
            c++;
            if(c > 333)
            {
                printf("\033[1m\x1B[31mERROR: truncate() in forceTruncate() has failed for '%s'.\x1B[0m\033[0m\n", file);
                err++;
                close(f);
                return;
            }
        }

        close(f);
    }
}

//https://stackoverflow.com/questions/14293095/is-there-a-library-function-to-determine-if-an-ip-address-ipv4-and-ipv6-is-pri
int isPrivateAddress(const uint32_t iip)
{
    const uint32_t ip = ntohl(iip); ///Convert from network to host byte order

    uint8_t b1=0, b2, b3, b4;
    b1 = (uint8_t)(ip >> 24);
    b2 = (uint8_t)((ip >> 16) & 0x0ff);
    b3 = (uint8_t)((ip >> 8) & 0x0ff);
    b4 = (uint8_t)(ip & 0x0ff);

    // 10.x.y.z
    if (b1 == 10)
        return 1;

    // 172.16.0.0 - 172.31.255.255
    if ((b1 == 172) && (b2 >= 16) && (b2 <= 31))
        return 1;

    // 192.168.0.0 - 192.168.255.255
    if ((b1 == 192) && (b2 == 168))
        return 1;

    return 0;
}

uint getReplayRate()
{
    // This changes the delay in microseconds between each transaction sent during a block replay to a peer
    // for example; 10,000 = 1,000 transactions a second, each transaction is 147 bytes, that a total of 1000*147 = 147,000 bytes a second (147kb a sec) per peer.
    const time_t lt = time(0);
    const struct tm* tmi = localtime(&lt);
    
    if(tmi->tm_hour == 0)        return 10000;
    else if(tmi->tm_hour == 1)   return 10000;
    else if(tmi->tm_hour == 2)   return 10000;
    else if(tmi->tm_hour == 3)   return 10000;
    else if(tmi->tm_hour == 4)   return 10000;
    else if(tmi->tm_hour == 5)   return 10000;
    else if(tmi->tm_hour == 6)   return 10000;
    else if(tmi->tm_hour == 7)   return 10000;
    else if(tmi->tm_hour == 8)   return 10000;
    else if(tmi->tm_hour == 9)   return 10000;
    else if(tmi->tm_hour == 10)  return 30000;
    else if(tmi->tm_hour == 11)  return 30000;
    else if(tmi->tm_hour == 12)  return 30000;
    else if(tmi->tm_hour == 13)  return 40000;
    else if(tmi->tm_hour == 14)  return 40000;
    else if(tmi->tm_hour == 15)  return 40000;
    else if(tmi->tm_hour == 16)  return 40000;
    else if(tmi->tm_hour == 17)  return 30000;
    else if(tmi->tm_hour == 18)  return 30000;
    else if(tmi->tm_hour == 19)  return 30000;
    else if(tmi->tm_hour == 20)  return 30000;
    else if(tmi->tm_hour == 21)  return 20000;
    else if(tmi->tm_hour == 22)  return 10000;
    else if(tmi->tm_hour == 23)  return 10000;
    else if(tmi->tm_hour == 24)  return 10000;

    // if(tmi->tm_hour == 0)        return 40000;
    // else if(tmi->tm_hour == 1)   return 40000;
    // else if(tmi->tm_hour == 2)   return 40000;
    // else if(tmi->tm_hour == 3)   return 10000;
    // else if(tmi->tm_hour == 4)   return 10000;
    // else if(tmi->tm_hour == 5)   return 10000;
    // else if(tmi->tm_hour == 6)   return 10000;
    // else if(tmi->tm_hour == 7)   return 40000;
    // else if(tmi->tm_hour == 8)   return 40000;
    // else if(tmi->tm_hour == 9)   return 40000;
    // else if(tmi->tm_hour == 10)  return 60000;
    // else if(tmi->tm_hour == 11)  return 120000;
    // else if(tmi->tm_hour == 12)  return 120000;
    // else if(tmi->tm_hour == 13)  return 120000;
    // else if(tmi->tm_hour == 14)  return 120000;
    // else if(tmi->tm_hour == 15)  return 120000;
    // else if(tmi->tm_hour == 16)  return 120000;
    // else if(tmi->tm_hour == 17)  return 120000;
    // else if(tmi->tm_hour == 18)  return 120000;
    // else if(tmi->tm_hour == 19)  return 120000;
    // else if(tmi->tm_hour == 20)  return 120000;
    // else if(tmi->tm_hour == 21)  return 60000;
    // else if(tmi->tm_hour == 22)  return 40000;
    // else if(tmi->tm_hour == 23)  return 40000;
    // else if(tmi->tm_hour == 24)  return 40000;
    
    return 120000;
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/*
.
.
.
.
. ~ Unique Capping Code
.
.   Adequate and fast unique store implementation forked from
.   https://github.com/USTOR-C/USTOR-64/blob/master/ustor.c
.   James William Fletcher
.
.   It's light weight, thread-safe, but not mission-critical,
.   there will be collisions from time to time.
.
*/

struct site //8 bytes, no padding.
{
    unsigned short uid_high;
    unsigned short uid_low;
    uint expire_epoch;
};

//Our buckets
struct site *sites;

void init_sites()
{
    sites = malloc(MAX_SITES * sizeof(struct site));
    if(sites == NULL)
    {
        perror("Failed to allocate memory for the Unique Store.\n");
        exit(0);
    }

    for(int i = 0; i < MAX_SITES; ++i)
    {
        sites[i].uid_high = 0;
        sites[i].uid_low = 0;
        sites[i].expire_epoch = 0;
    }
}

//Check against all uid in memory for a match
int has_uid(const uint64_t uid) //Pub
{
    //Find site index
    const uint site_index = uid % MAX_SITES;

    //Reset if expire_epoch dictates this site bucket is expired 
    if(time(0) >= sites[site_index].expire_epoch) //Threaded race conditions are not an issue here.
    {
        sites[site_index].uid_low = 0;
        sites[site_index].uid_high = 0;
        sites[site_index].expire_epoch = 0;
    }

    //Check the ranges
    unsigned short idfar = (uid % (sizeof(unsigned short)-1))+1;
    if(idfar >= sites[site_index].uid_low && idfar <= sites[site_index].uid_high)
        return 1; //it's blocked

    //no uid
    return 0;
}

//Set's idfa,
void add_uid(const uint64_t uid, const uint expire_seconds) //Pub
{
    //Find site index
    const uint site_index = uid % MAX_SITES;

    //Reset if expire_epoch dictates this site bucket is expired 
    if(time(0) >= sites[site_index].expire_epoch)
    {
        sites[site_index].uid_low = 0;
        sites[site_index].uid_high = 0;
        sites[site_index].expire_epoch = time(0)+expire_seconds;
    }

    //Set the ranges
    unsigned short idfar = (uid % (sizeof(unsigned short)-1))+1;
    if(idfar < sites[site_index].uid_low || sites[site_index].uid_low == 0)
    {
        sites[site_index].uid_low = idfar;
    }
    if(idfar > sites[site_index].uid_high || sites[site_index].uid_high == 0)
    {
        sites[site_index].uid_high = idfar;
    }
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Mining
*/

//Vector3
struct vec3
{
    uint16_t x,y,z;
};
typedef struct vec3 vec3;

//Get normal angle
inline static double gNa(const vec3* a, const vec3* b)
{
    const double dot = ((double)(a->x) * (double)(b->x)) + ((double)(a->y) * (double)(b->y)) + (double)((a->z) * (double)(b->z)); //dot product of both vectors
    const double m1 = sqrt((double)((a->x) * (double)(a->x)) + (double)((a->y) * (double)(a->y)) + (double)((a->z) * (double)(a->z))); //magnitude
    const double m2 = sqrt((double)((b->x) * (double)(b->x)) + (double)((b->y) * (double)(b->y)) + (double)((b->z) * (double)(b->z))); //magnitude

    if((m1 == 0 && m2 == 0) || dot == 0)
        return 1; //returns angle that is too wide, exclusion / (aka/equiv) ret0

    return dot / (m1*m2); //Should never divide by 0
}

inline static double getMiningDifficulty()
{
    // const time_t lt = time(0);
    // const struct tm* tmi = gmtime(&lt);
    // return (double)(tmi->tm_hour+1) * 0.01; 
    return 0.24;
}

inline static uint64_t diff2val(const double ra)
{
    return (uint64_t)floor(( 1000 + ( 10000*(1-(ra*4.166666667)) ) )+0.5);
}

//This is the algorthm to check if a genesis address is a valid "SubGenesis" address
uint64_t isSubGenesisAddressMine(uint8_t *a)
{
    //Requesting the balance of a possible existing subG address

    vec3 v[5]; //Vectors

    char *ofs = a;
    memcpy(&v[0].x, ofs, sizeof(uint16_t));
    memcpy(&v[0].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[0].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[1].x, ofs, sizeof(uint16_t));
    memcpy(&v[1].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[1].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[2].x, ofs, sizeof(uint16_t));
    memcpy(&v[2].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[2].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[3].x, ofs, sizeof(uint16_t));
    memcpy(&v[3].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[3].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[4].x, ofs, sizeof(uint16_t));
    memcpy(&v[4].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[4].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    const double a1 = gNa(&v[0], &v[3]);
    const double a2 = gNa(&v[3], &v[2]);
    const double a3 = gNa(&v[2], &v[1]);
    const double a4 = gNa(&v[1], &v[4]);

    //All normal angles a1-a4 must be under this value
    const double min = 0.24;
    
    //Was it a straight hit?
    if(a1 < min && a2 < min && a3 < min && a4 < min)
    {
        //Calculate and return value of address mined
        const double at = (a1+a2+a3+a4);
        if(at <= 0)
            return 0; //not want zero address.
        const double ra = at/4;
        const double mn = 4.166666667; //(1/min);
        const uint64_t rv = (uint64_t)floor(( 1000 + ( 10000*(1-(ra*mn)) ) )+0.5);

        //Illustrate the hit
        setlocale(LC_NUMERIC, "");
        printf("\x1B[33msubG\x1B[0m: %.8f - %.8f - %.8f - %.8f - %'.3f VFC < %.3f\n\n", a1, a2, a3, a4, toDB(rv), ra);

        return rv;
    }

    //Print the occasional "close hit"
    const double soft = 0.1;
    if(a1 < min+soft && a2 < min+soft && a3 < min+soft && a4 < min+soft)
        printf("\x1B[33mx\x1B[0m: %.8f - %.8f - %.8f - %.8f\n", a1, a2, a3, a4);

    return 0;

}

//This is the algorthm to check if a genesis address is a valid "SubGenesis" address
uint64_t isSubGenesisAddress(uint8_t *a, const uint fr)
{
    //Is this requesting the genesis balance
    if(memcmp(a, genesis_pub, ECC_CURVE+1) == 0)
    {
        //Get the tax
        struct stat st;
        stat(CHAIN_FILE, &st);
        uint64_t ift = 0;
        if(st.st_size > 0)
            ift = (uint64_t)st.st_size / 133;
        else
            return 0;
        
        ift *= INFLATION_TAX; //every transaction inflates vfc by 1 VFC (1000v). This is a TAX paid to miners.
        return ift;
    }

    //Requesting the balance of a possible existing subG address

    vec3 v[5]; //Vectors

    char *ofs = a;
    memcpy(&v[0].x, ofs, sizeof(uint16_t));
    memcpy(&v[0].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[0].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[1].x, ofs, sizeof(uint16_t));
    memcpy(&v[1].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[1].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[2].x, ofs, sizeof(uint16_t));
    memcpy(&v[2].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[2].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[3].x, ofs, sizeof(uint16_t));
    memcpy(&v[3].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[3].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    ofs = ofs + (sizeof(uint16_t)*3);
    memcpy(&v[4].x, ofs, sizeof(uint16_t));
    memcpy(&v[4].y, ofs + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&v[4].z, ofs + (sizeof(uint16_t)*2), sizeof(uint16_t));

    const double a1 = gNa(&v[0], &v[3]);
    const double a2 = gNa(&v[3], &v[2]);
    const double a3 = gNa(&v[2], &v[1]);
    const double a4 = gNa(&v[1], &v[4]);

    //All normal angles a1-a4 must be under this value
    //const double min = fr == 0 ? getMiningDifficulty() : 0.24;
    const double min = 0.24;
    
    //Was it a straight hit?
    if(a1 < min && a2 < min && a3 < min && a4 < min)
    {
        //Calculate and return value of address mined
        const double at = (a1+a2+a3+a4);
        if(at <= 0)
            return 0; //not want zero address.
        const double ra = at/4;
        const double mn = 4.166666667; //(1/min);
        const uint64_t rv = (uint64_t)floor(( 1000 + ( 10000*(1-(ra*mn)) ) )+0.5);

        return rv;
    }

    return 0;

}


///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Structures

    sig - signature store
    addr - public/private addr store
    trans - transaction data structure

*/

struct addr
{
    uint8_t key[ECC_CURVE+1];
};
typedef struct addr addr;

struct sig
{
    uint8_t key[ECC_CURVE*2];
};
typedef struct sig sig;

struct trans
{
    uint64_t uid;
    addr from;
    addr to;
    mval amount;
    sig owner;
};

void makHash(uint8_t *hash, const struct trans* t)
{
    sha3_context c;
    sha3_Init256(&c);
    sha3_Update(&c, t, sizeof(struct trans));
    sha3_Finalize(&c);
    memcpy(hash, &c.sb, ECC_CURVE);
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ P2P Tracker

    isMasterNode() - Check if address is master node
    setMasterNode() - Reset's the peers list setting master node at index 0

    resyncBlocks() - Download most recent blockchain version from master
    verifyChain() - verify blockchain has the original genesis block.
    
    addPeer() - Add a peer address to the peers (if free space available)
    isPeer() - Check if peer already exists in list.
    
    peersBroadcast() - Broadcast a packet to the peers (skipping master)
    sendMaster() - Only send packet to master

*/

//General peer tracking
uint peers[MAX_PEERS]; //Peer IPv4 addresses
time_t peer_timeouts[MAX_PEERS]; //Peer timeout UNIX epoch stamps
uint num_peers = 0; //Current number of indexed peers
uint peer_tcount[MAX_PEERS]; //Amount of transactions relayed by peer
char peer_ua[MAX_PEERS][64]; //Peer user agent
uint64_t peer_ba[MAX_PEERS]; //Balance Aggregation

uint64_t trueBalance()
{
    uint64_t v[num_peers];
    uint c[num_peers];
    uint vm = 0;
    for(uint i = 0; i < num_peers; i++)
        c[i] = 0;
    for(uint i = 0; i < num_peers; i++)
    {
        if(peer_ba[i] == 0)
            continue;
        uint t = 0;
        for(uint i2 = 0; i2 < vm; i2++)
        {
            if(v[i2] == peer_ba[i])
            {
                c[i2]++;
                t = 1;
                break;
            }
        }
        if(t == 0)
        {
            v[vm] = peer_ba[i];
            c[vm]++;
            vm++;
        }
    }

    uint hc = 0;
    uint64_t hv = 0;
    for(uint i = 0; i < vm; i++)
    {
        if(c[i] > hc)
        {
            hc = c[i];
            hv = v[i];
        }
    }
    return hv;
}

uint countPeers()
{
    uint c = 0;
    for(uint i = 0; i < MAX_PEERS; i++)
    {
        if(peers[i] == 0)
            return c;
        c++;
    }
    return c;
}

uint countLivingPeers()
{
    uint c = 0;
    for(uint i = 0; i < num_peers; i++)
    {
        const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS);
        if(pd <= PING_INTERVAL*4)
            c++;
    }
    return c;
}

uint csend(const uint ip, const char* send, const size_t len)
{
    struct sockaddr_in server;

    int s;
    if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        return 0;

    memset((char*)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(gport);
    server.sin_addr.s_addr = ip;

    if(sendto(s, send, len, 0, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        err++;
        close(s);
        return 0;
    }
    
    close(s);
    return 1;
}

void scanPeers()
{
    printf("\x1B[33m\nIt seems the Masternode is offline? We will now scan the entire IPv4 range of ~4.3 billion checking for peers.\x1B[0m\n");

    time_t s = 0;
    for(uint i = 0; i < 4294967294; ++i)
    {
        if(isPrivateAddress(i) == 1)
            continue;

        if(time(0) > s)
        {
            setlocale(LC_NUMERIC, "");
            printf("%'u of 4,294,967,294 scanned.\n", i);
            s = time(0)+3;
        }

        csend(i, mid, 8);
    }
}

uint verifyChain(const char* path)
{
    //Genesis Public Key
    uint8_t gpub[ECC_CURVE+1];
    size_t len = ECC_CURVE+1;
    b58tobin(gpub, &len, "foxXshGUtLFD24G9pz48hRh3LWM58GXPYiRhNHUyZAPJ", 44);

    //Ok let's check that genesis trans and work through chain
    FILE* f = fopen(path, "r");
    if(f)
    {
        //Is legit genesis block?
        struct trans t;
        if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
        {
            if(memcmp(t.to.key, gpub, ECC_CURVE+1) != 0)
                return 0;
        }
        else
        {
            fclose(f);
            return 0; //Could not read the first trans of the block file, fail.
        }

        //Done
        fclose(f);
    }
    else
    {
        printf("Look's like the blocks.dat cannot be found please make sure you chmod 700 ~/vfc\n");
        return 0;
    }
    
    //Look's legit
    return 1;
}

uint isMasterNode(const uint ip)
{
    if(ip == peers[0])
        return 1;
    return 0;
}

void setMasterNode()
{
    memset(peers, 0, sizeof(uint)*MAX_PEERS);
    memset(peer_timeouts, 0, sizeof(uint)*MAX_PEERS);
    struct in_addr a;
    inet_aton(master_ip, &a);
    peers[0] = a.s_addr;
    sprintf(peer_ua[0], "VFC-MASTER");
    num_peers = 1;
}

void peersBroadcast(const char* dat, const size_t len)
{
    for(uint i = 1; i < num_peers; ++i) //Start from 1, skip master
        csend(peers[i], dat, len);
}

void triBroadcast(const char* dat, const size_t len)
{
    if(num_peers > 3)
    {
        uint si = qRand(1, num_peers-1);
        do
        {
            const uint pd = time(0)-(peer_timeouts[si]-MAX_PEER_EXPIRE_SECONDS);
            if(pd <= PING_INTERVAL*4)
                break;
            si++;
        }
        while(si < num_peers);

        if(si == num_peers)
            csend(peers[qRand(1, num_peers-1)], dat, len);
        else
            csend(peers[si], dat, len);
    }
    else
    {
        if(num_peers > 0)
            csend(peers[1], dat, len);
        if(num_peers > 1)
            csend(peers[2], dat, len);
        if(num_peers > 2)
            csend(peers[3], dat, len);
    }
}

void resyncBlocks()
{
#if MASTER_NODE == 0
    //Resync from Master
    csend(peers[0], "r", 1);
#endif

    //allow replay from 6 random peers
    for(int i = 0; i < 6; i++)
    {

        //Also Sync from a Random Node (Sync is called fairly often so eventually the random distribution across nodes will fair well)
        replay_allow[i] = 0;
        if(num_peers > 1)
        {
            //Look for a living peer
            uint si = qRand(1, num_peers-1); // start from random offset
            do // find next living peer from offset
            {
                const uint pd = time(0)-(peer_timeouts[si]-MAX_PEER_EXPIRE_SECONDS); //ping delta
                if(pd <= PING_INTERVAL*4)
                    break;
                si++;
            }
            while(si < num_peers);

            if(si == num_peers)
                replay_allow[i] = peers[qRand(1, num_peers-1)];
            else
                replay_allow[i] = peers[si];
        }
        else if(num_peers == 1)
        {
            replay_allow[i] = peers[1];
        }

        //Alright ask this peer to replay to us too
        if(num_peers > 1 && replay_allow[i] != 0)
            csend(replay_allow[i], "r", 1);
  
    }
    
    //`hk The master resyncs off everyone
// #if MASTER_NODE == 1
//         peersBroadcast("r", 1);
// #endif

    //Set the file memory
    forceWrite(".vfc/rp.mem", &replay_allow, sizeof(uint)*6);
}

uint sendMaster(const char* dat, const size_t len)
{
    return csend(peers[0], dat, len);
}

uint isPeer(const uint ip)
{
    for(uint i = 0; i < num_peers; ++i)
        if(peers[i] == ip)
            return 1;
    return 0;
}

int getPeer(const uint ip)
{
    for(uint i = 0; i < num_peers; ++i)
        if(peers[i] == ip)
            return i;
    return -1;
}

#if MASTER_NODE == 1
void RewardPeer(const uint ip, const char* pubkey)
{
    //Only reward if ready
    if(rewardpaid == 1)
        return;

    //Only reward the eligible peer
    if(peers[rewardindex] != ip)
        return;

    //Base amount
    double amount = 3.000;

    //Wrong / not latest version? Low reward
    if(strstr(peer_ua[rewardindex], version) == NULL)
        amount = 0;

    //Clean the input ready for sprintf (exploit vector potential otherwise)
    char sa[MIN_LEN];
    memset(sa, 0, sizeof(sa));
    const int sal = strlen(pubkey);
    memcpy(sa, pubkey, sal);
    for(int i = 1; i < sal; ++i)
        if(isalonu(sa[i]) == 0)
            sa[i] = 0x00;

    //Construct command
    char cmd[2048];
    sprintf(cmd, reward_command, sa, amount);

    //Drop info
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    timestamp();
    printf("Reward Yapit (%u):%s, %.3f, %s\n", rewardindex, sa, amount, inet_ntoa(ip_addr));

    pid_t fork_pid = fork();
    if(fork_pid == 0)
    {
        //Just send the transaction using the console, much easier
        system(cmd);
        exit(0);
    }

    rewardpaid = 1;
}
#endif

//Peers are only replaced if they have not responded in a week, otherwise we still consider them contactable until replaced.
uint addPeer(const uint ip)
{
    //Never add local host
    if(ip == inet_addr("127.0.0.1")) //inet_addr("127.0.0.1") //0x0100007F
        return 0;

    //Or local network address
    if(isPrivateAddress(ip) == 1)
        return 0;

    //Is already in peers?
    uint freeindex = 0;
    for(uint i = 0; i < num_peers; ++i)
    {
        if(peers[i] == ip)
        {
            peer_timeouts[i] = time(0) + MAX_PEER_EXPIRE_SECONDS;
            peer_tcount[i]++;
            return 0; //exists
        }

        if(freeindex == 0 && i != 0 && peer_timeouts[i] < time(0)) //0 = Master, never a free slot.
            freeindex = i;
    }

    //Try to add to a free slot first
    if(num_peers < MAX_PEERS)
    {
        peers[num_peers] = ip;
        peer_timeouts[num_peers] = time(0) + MAX_PEER_EXPIRE_SECONDS;
        peer_tcount[num_peers] = 1;
        num_peers++;
        return 1;
    }
    else if(freeindex != 0) //If not replace a node that's been quiet for more than three hours
    {
        peers[freeindex] = ip;
        peer_timeouts[freeindex] = time(0) + MAX_PEER_EXPIRE_SECONDS;
        peer_tcount[freeindex] = 1;
        return 1;
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Transaction Queue

    aQue() - Add Transaction to Queue
    gQue() - Return pointer to fist valid transaction
    gQueSize() - Number of items in Queue

*/

//The Variables that make up `the Queue`
struct trans tq[MAX_TRANS_QUEUE];
uint ip[MAX_TRANS_QUEUE];
uint ipo[MAX_TRANS_QUEUE];
unsigned char replay[MAX_TRANS_QUEUE]; // 1 = not replay, 0 = replay
time_t delta[MAX_TRANS_QUEUE];

//size of queue
uint gQueSize()
{
    uint size = 0;
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].amount != 0 && time(0) - delta[i] > 2)
            size++;
    }
    return size;
}

//Add a transaction to the Queue
uint aQue(struct trans *t, const uint iip, const uint iipo, const unsigned char ir)
{
    //If amount is 0
    if(t->amount == 0)
        return 0; //Don't tell the other peers, pointless transaction

    //Check if duplicate transaction
    int freeindex = -1;
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].amount != 0)
        {
            //Is this a possible double spend?
            if(ir == 1 && replay[i] == 1)
            {
                if(memcmp(tq[i].from.key, t->from.key, ECC_CURVE+1) == 0 && memcmp(tq[i].to.key, t->to.key, ECC_CURVE+1) != 0)
                {
                    //Log both blocks in bad_blocks
                    FILE* f = fopen(BADCHAIN_FILE, "a");
                    if(f)
                    {
                        fwrite(&tq[i], sizeof(struct trans), 1, f);
                        fwrite(t, sizeof(struct trans), 1, f);
                        fclose(f);
                    }
                    tq[i].amount = 0; //It looks like it could be a double spend, terminate the original transaction
                    return 1; //Don't process this one either and tell our peers about this dodgy action so that they terminate also.
                }
            }

            //UID already in queue?
            if(tq[i].uid == t->uid)
                return 0; //It's not a double spend, just a repeat, don't tell our peers
        }
        
        if(freeindex == -1 && tq[i].amount == 0)
            freeindex = i;
    }

    //if fresh transaction add at available slot
    if(freeindex != -1)
    {
        memcpy(&tq[freeindex], t, sizeof(struct trans));
        ip[freeindex] = iip;
        ipo[freeindex] = iipo;
        replay[freeindex] = ir;
        delta[freeindex] = time(0);
    }
    // else
    // {
    //     printf("Warning: QUE FULL %u\n", gQueSize());
    // }

    //Success
    return 1;
}

//pop the first living transaction index off the Queue
int gQue()
{
    const uint mi = qRand(0, MAX_TRANS_QUEUE-1);
    for(uint i = mi; i > 0; i--) //Check backwards first, que is stacked left to right
    {
        if(tq[i].amount != 0)
            if(time(0) - delta[i] > 2 || replay[i] == 1) //Only process transactions more than 3 second old [replays are instant]
                return i;
    }
    for(uint i = mi; i < MAX_TRANS_QUEUE; i++) ///check into the distance
    {
        if(tq[i].amount != 0)
            if(time(0) - delta[i] > 2 || replay[i] == 1) //Only process transactions more than 3 second old [replays are instant]
                return i;
    }
    return -1;
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Blockchain Transversal & Functions
*/


//Get mined supply
uint64_t getMinedSupply()
{
    uint64_t rv = 0;
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);

        struct trans t;
        for(size_t i = sizeof(struct trans); i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in getMinedSupply() has failed.\x1B[0m\033[0m\n");
                    err++;
                    fclose(f);
                    return 0;
                }
                if(f == NULL)
                    continue;
            }

            if(memcmp(t.from.key, genesis_pub, ECC_CURVE+1) != 0)
            {
                const uint64_t w = isSubGenesisAddress(t.from.key, 1);
                if(w > 0)
                {
                    rv += w;
                }
            }
            
        }

        fclose(f);
    }
    return rv;
}


//Get circulating supply
uint64_t getCirculatingSupply()
{
    //Get the tax
    struct stat st;
    stat(CHAIN_FILE, &st);
    uint64_t ift = 0;
    if(st.st_size > 0)
        ift = (uint64_t)st.st_size / 133;
    ift *= INFLATION_TAX; //every transaction inflates vfc by 1 VFC (1000v). This is a TAX paid to miners.

    uint64_t rv = (ift / 100) * 20; // 20% of the ift tax
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);

        struct trans t;
        for(size_t i = sizeof(struct trans); i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in getCirculatingSupply() has failed.\x1B[0m\033[0m\n");
                    err++;
                    fclose(f);
                    return 0;
                }
                if(f == NULL)
                    continue;
            }
            
            //All the paid out subG address values
            if(memcmp(t.from.key, genesis_pub, ECC_CURVE+1) != 0)
            {
                const uint64_t w = isSubGenesisAddress(t.from.key, 1);
                if(w > 0)
                {
                    rv += w;
                }
            }
            else
            {
                rv += t.amount; //all of the transactions leaving the genesis key
            }
            
            
        }

        fclose(f);
    }
    return rv;
}

//Replay thread queue
uint32_t replay_peers[MAX_THREADS_BUFF];

//Get replay peer
uint32_t getRP()
{
    for(int i = 0; i < MAX_THREADS; ++i)
    {
        if(replay_peers[i] != 0)
        {
            const uint32_t r = replay_peers[i];
            replay_peers[i] = 0;
            return r;
        }
    }
    return 0;
}

//Set replay peer ip
void setRP(const uint32_t ip)
{
    for(int i = 0; i < MAX_THREADS; ++i)
    {
        if(replay_peers[i] == 0)
        {
            replay_peers[i] = ip;
            break;
        } 
    }
}

//Replay blocks to x address
void replayBlocks(const uint ip)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;

    const uint replay_rate = getReplayRate();

    //Send block height
    struct stat st;
    stat(CHAIN_FILE, &st);
    if(st.st_size > 0)
    {
        char pc[MIN_LEN];
        pc[0] = 'h';
        char* ofs = pc + 1;
        const uint height = st.st_size;
        memcpy(ofs, &height, sizeof(uint));
        csend(ip, pc, 1+sizeof(uint));
        printf("Replaying: %.1f kb to %s\n", (double) ( (sizeof(struct trans)*REPLAY_SIZE) + (sizeof(struct trans)*3333)) / 1000, inet_ntoa(ip_addr));
    }

    //Replay blocks
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);
        
        // *
        //  Always send your most recent graph-ends first
        // *

        size_t end = len-(3333*sizeof(struct trans)); //top 3333 transactions
        struct trans t;
        for(size_t i = len-sizeof(struct trans); i > end; i -= sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in replayBlocks() #1 has failed for peer %s\x1B[0m\033[0m\n", inet_ntoa(ip_addr));
                    err++;
                    fclose(f);
                    return;
                }

                if(f == NULL)
                    continue;
            }

            //Generate Packet (pc)
            const size_t len = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
            char pc[MIN_LEN];
            pc[0] = 'p'; //This is a re*P*lay
            char* ofs = pc + 1;
            memcpy(ofs, &t.uid, sizeof(uint64_t));
            ofs += sizeof(uint64_t);
            memcpy(ofs, t.from.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, t.to.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, &t.amount, sizeof(mval));
            ofs += sizeof(mval);
            memcpy(ofs, t.owner.key, ECC_CURVE*2);
            csend(ip, pc, len);

            //333 = 3k, 211 byte packets / 618kb a second
            #if MASTER_NODE == 1
                usleep(40000); //
            #else
                usleep(replay_rate); //
            #endif
        }

        // *
        //  Now send a random block of transaction data of REPLAY_SIZE
        // *

        //Pick a random block of data from the chain of the specified REPLAY_SIZE
        const size_t rpbs = (sizeof(struct trans)*REPLAY_SIZE);
        const size_t lp = len / rpbs; //How many REPLAY_SIZE fit into the current blockchain length
        const size_t st = sizeof(struct trans) + (rpbs * qRand(1, lp-1)); //Start at one of these x offsets excluding the end of the last block (no more blocks after this point)
        end = st+rpbs; //End after that offset + REPLAY_SIZE amount of transactions later

        for(size_t i = st; i < len && i < end; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in replayBlocks() #2 has failed for peer %s\x1B[0m\033[0m\n", inet_ntoa(ip_addr));
                    err++;
                    fclose(f);
                    return;
                }
                if(f == NULL)
                    continue;
            }

            //Generate Packet (pc)
            const size_t len = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
            char pc[MIN_LEN];
            pc[0] = 'p'; //This is a re*P*lay
            char* ofs = pc + 1;
            memcpy(ofs, &t.uid, sizeof(uint64_t));
            ofs += sizeof(uint64_t);
            memcpy(ofs, t.from.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, t.to.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, &t.amount, sizeof(mval));
            ofs += sizeof(mval);
            memcpy(ofs, t.owner.key, ECC_CURVE*2);
            csend(ip, pc, len);

            //333 = 3k, 211 byte packets / 618kb a second
            #if MASTER_NODE == 1
                usleep(40000); //
            #else
                usleep(replay_rate); //
            #endif
            
        }

        fclose(f);
    }
}
void *replayBlocksThread(void *arg)
{
    //Is thread needed?
    pthread_mutex_lock(&mutex1);
    const uint ip = getRP(); //This contains a write
    if(ip == 0)
    {
        threads--;
        pthread_mutex_unlock(&mutex1);
        return 0;
    }
    pthread_mutex_unlock(&mutex1);

    //Prep the thread
    chdir(getHome());
    nice(19); //Very low priority thread

    //Replay the blocks
    replayBlocks(ip);

    //End the thread
    pthread_mutex_lock(&mutex1);
    threads--;
    for(int i = 0; i < MAX_THREADS; i++)
        if(thread_ip[i] == ip)
            thread_ip[i] = 0;
    pthread_mutex_unlock(&mutex1);
}


//Launch a replay thread
void launchReplayThread(const uint32_t ip)
{
    //Are there enough thread slots left?
    if(threads >= MAX_THREADS)
        return;

    //Are we already replaying to this IP address?
    uint cp = 1;
    for(uint i = 0; i < MAX_THREADS; i++)
        if(thread_ip[i] == ip)
            cp = 0;

    //We're not replaying to this IP address, so let's launch a replay thread
    if(cp == 1)
    {
        setRP(ip);

        pthread_t tid;
        if(pthread_create(&tid, NULL, replayBlocksThread, NULL) == 0)
        {
            pthread_detach(tid);
            pthread_mutex_lock(&mutex1);
            thread_ip[threads] = ip;
            threads++;
            pthread_mutex_unlock(&mutex1);
        }
    }
}

//repair chain
void truncate_at_error(const char* file, const uint num)
{
    int f = open(file, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

            struct trans t;
            time_t st = time(0);
            for(size_t i = sizeof(struct trans)*((len/144)-num); i < len; i += sizeof(struct trans))
            {
                memcpy(&t, m+i, sizeof(struct trans));

                if(time(0) > st)
                {
                    printf("head: %li / %li\n", i/144, len/144);
                    st = time(0) + 9;
                }

                //Make original
                struct trans to;
                memset(&to, 0, sizeof(struct trans));
                to.uid = t.uid;
                memcpy(to.from.key, t.from.key, ECC_CURVE+1);
                memcpy(to.to.key, t.to.key, ECC_CURVE+1);
                to.amount = t.amount;

                //Lets verify if this signature is valid
                uint8_t thash[ECC_CURVE];
                makHash(thash, &to);
                if(ecdsa_verify(t.from.key, thash, t.owner.key) == 0)
                {
                    //Alright this trans is invalid

                    char topub[MIN_LEN];
                    memset(topub, 0, sizeof(topub));
                    size_t len = MIN_LEN;
                    b58enc(topub, &len, t.to.key, ECC_CURVE+1);

                    char frompub[MIN_LEN];
                    memset(frompub, 0, sizeof(frompub));
                    len = MIN_LEN;
                    b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

                    setlocale(LC_NUMERIC, "");
                    printf("%s > %s : %'.3f\n", frompub, topub, toDB(t.amount));

                    forceTruncate(file, i);
                    printf("Trunc at: %li\n", i);
                    munmap(m, len);
                    return;
                }
            }

            munmap(m, len);
        }

        close(f);
    }

}

//dump all trans
void dumptrans()
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in dumptrans() has failed.\x1B[0m\033[0m\n");
                    fclose(f);
                    return;
                }
                if(f == NULL)
                    continue;
            }

            char topub[MIN_LEN];
            memset(topub, 0, sizeof(topub));
            size_t len = MIN_LEN;
            b58enc(topub, &len, t.to.key, ECC_CURVE+1);

            char frompub[MIN_LEN];
            memset(frompub, 0, sizeof(frompub));
            len = MIN_LEN;
            b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

            setlocale(LC_NUMERIC, "");
            printf("%s > %s : %'.3f\n", frompub, topub, toDB(t.amount));
        }

        fclose(f);
    }
}

//dump all bad trans
void dumpbadtrans()
{
    FILE* f = fopen(BADCHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(BADCHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in dumpbadtrans() has failed.\x1B[0m\033[0m\n");
                    fclose(f);
                    return;
                }
                if(f == NULL)
                    continue;
            }

            char topub[MIN_LEN];
            memset(topub, 0, sizeof(topub));
            size_t len = MIN_LEN;
            b58enc(topub, &len, t.to.key, ECC_CURVE+1);

            char frompub[MIN_LEN];
            memset(frompub, 0, sizeof(frompub));
            len = MIN_LEN;
            b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

            setlocale(LC_NUMERIC, "");
            printf("%s > %s : %'.3f\n", frompub, topub, toDB(t.amount));
        
        }

        fclose(f);
    }
}

//print received transactions
void printIns(addr* a)
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in printIns() has failed.\x1B[0m\033[0m\n");
                    fclose(f);
                    return;
                }
                if(f == NULL)
                    continue;
            }

            if(memcmp(&t.to.key, a->key, ECC_CURVE+1) == 0)
            {
                char pub[MIN_LEN];
                memset(pub, 0, sizeof(pub));
                size_t len = MIN_LEN;
                b58enc(pub, &len, t.from.key, ECC_CURVE+1);
                setlocale(LC_NUMERIC, "");
                //printf("%lu: %s > %'.3f\n", t.uid, pub, toDB(t.amount));
                printf("%s > %'.3f\n", pub, toDB(t.amount));
            }
            
        }

        fclose(f);
    }
}

//print sent transactions
void printOuts(addr* a)
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > 333)
                {
                    printf("\033[1m\x1B[31mERROR: fread() in printOuts() has failed.\x1B[0m\033[0m\n");
                    fclose(f);
                    return;
                }
                if(f == NULL)
                    continue;
            }

            if(memcmp(&t.from.key, a->key, ECC_CURVE+1) == 0)
            {
                char pub[MIN_LEN];
                memset(pub, 0, sizeof(pub));
                size_t len = MIN_LEN;
                b58enc(pub, &len, t.to.key, ECC_CURVE+1);
                setlocale(LC_NUMERIC, "");
                //printf("%lu: %s > %'.3f\n", t.uid, pub, toDB(t.amount));
                printf("%s > %'.3f\n", pub, toDB(t.amount));
            }
            
        }

        fclose(f);
    }
}

//get balance
uint64_t getBalanceLocal(addr* from)
{
    //Get local Balance
    int64_t rv = isSubGenesisAddress(from->key, 1);

    if(is8664 == 1) //mmap on x86_64
    {
        int f = open(CHAIN_FILE, O_RDONLY);
        if(f)
        {
            const size_t len = lseek(f, 0, SEEK_END);

            unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
            if(m != MAP_FAILED)
            {
                close(f);

                struct trans t;
                for(size_t i = 0; i < len; i += sizeof(struct trans))
                {
                    memcpy(&t, m+i, sizeof(struct trans));

                    if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                        rv += t.amount;
                    else if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                        rv -= t.amount;
                }

                munmap(m, len);
            }

            close(f);
        }
    }
    else //Other devices use a lower memory intensive version
    {
        FILE* f = fopen(CHAIN_FILE, "r");
        if(f)
        {
            fseek(f, 0, SEEK_END);
            const size_t len = ftell(f);

            struct trans t;
            for(size_t i = 0; i < len; i += sizeof(struct trans))
            {
                fseek(f, i, SEEK_SET);

                struct trans t;
                uint fc = 0;
                while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
                {
                    fclose(f);
                    f = fopen(CHAIN_FILE, "r");
                    fc++;
                    if(fc > 333)
                    {
                        printf("\033[1m\x1B[31mERROR: fread() in getBalanceLocal() has failed.\x1B[0m\033[0m\n");
                        err++;
                        fclose(f);
                        return 0;
                    }
                    if(f == NULL)
                        continue;
                }

                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }

            fclose(f);
        }
    }
    

    if(rv < 0)
        return 0;
    return rv;
}

//get balance
uint64_t getBalance(addr* from)
{
    //Reset our files & memory for last count
    balance_accumulator = 0;
    for(uint i = 0; i < MAX_PEERS; i++)
        peer_ba[i] = 0;
    forceWrite(".vfc/bal.mem", &balance_accumulator, sizeof(uint64_t));
    forceWrite(".vfc/balt.mem", &balance_accumulator, sizeof(uint64_t));

#if MASTER_NODE == 0
    //Tell peers to fill our accumulator
    char pc[ECC_CURVE+2];
    pc[0] = '$';
    char* ofs = pc+1;
    memcpy(ofs, from->key, ECC_CURVE+1);
    sendMaster(pc, ECC_CURVE+2);
    peersBroadcast(pc, ECC_CURVE+2);
#endif

    //Get local Balance
    const uint64_t rv = getBalanceLocal(from);
    return rv;
}

//Calculate if an address has the value required to make a transaction of x amount.
int hasbalance(const uint64_t uid, addr* from, mval amount)
{
    int64_t rv = isSubGenesisAddress(from->key, 0);

    if(is8664 == 1) //mmap on x86_64
    {
        int f = open(CHAIN_FILE, O_RDONLY);
        if(f)
        {
            const size_t len = lseek(f, 0, SEEK_END);

            unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
            if(m != MAP_FAILED)
            {
                close(f);

                struct trans t;
                for(size_t i = 0; i < len; i += sizeof(struct trans))
                {
                    if(t.uid == uid)
                    {
                        munmap(m, len);
                        // if(amount == 333)
                        // {
                        //     printf("hasbalance(): UID exists failed\n");
                        //     printf("%lu = %lu\n", t.uid, uid);
                        //     printf("%u = %u\n", t.amount, amount);
                        // }
                        return ERROR_UIDEXIST;
                    }
                    memcpy(&t, m+i, sizeof(struct trans));

                    if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                        rv += t.amount;
                    else if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                        rv -= t.amount;
                }

                munmap(m, len);
            }

            close(f);
        }
    }
    else //Other devices use a lower memory intensive version
    {
        FILE* f = fopen(CHAIN_FILE, "r");
        if(f)
        {
            fseek(f, 0, SEEK_END);
            const size_t len = ftell(f);

            struct trans t;
            for(size_t i = 0; i < len; i += sizeof(struct trans))
            {
                fseek(f, i, SEEK_SET);

                struct trans t;
                uint fc = 0;
                while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
                {
                    fclose(f);
                    f = fopen(CHAIN_FILE, "r");
                    fc++;
                    if(fc > 333)
                    {
                        printf("\033[1m\x1B[31mERROR: fread() in getBalanceLocal() has failed.\x1B[0m\033[0m\n");
                        err++;
                        fclose(f);
                        return 0;
                    }
                    if(f == NULL)
                        continue;
                }

                if(t.uid == uid)
                {
                    fclose(f);
                    return ERROR_UIDEXIST;
                }
                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }

            fclose(f);
        }
    }

    if(rv >= amount)
        return 1;
    else
        return 0;
}

//Is transaction unique
int isUnique(const uint64_t uid)
{
    if(is8664 == 1) //mmap on x86_64
    {
        int f = open(CHAIN_FILE, O_RDONLY);
        if(f)
        {
            const size_t len = lseek(f, 0, SEEK_END);

            unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
            if(m != MAP_FAILED)
            {
                close(f);

                uint64_t tuid = 0;
                for(size_t i = 0; i < len; i += sizeof(struct trans))
                {
                    memcpy(&tuid, m+i, sizeof(uint64_t));
                    if(tuid == uid)
                        return 0;
                }

                munmap(m, len);
            }

            close(f);
        }
    }
    else //Other devices use a lower memory intensive version
    {
        FILE* f = fopen(CHAIN_FILE, "r");
        if(f)
        {
            fseek(f, 0, SEEK_END);
            const size_t len = ftell(f);

            uint64_t tuid = 0;
            for(size_t i = 0; i < len; i += sizeof(struct trans))
            {
                fseek(f, i, SEEK_SET);

                uint64_t tuid = 0;
                uint fc = 0;
                while(fread(&tuid, 1, sizeof(uint64_t), f) != sizeof(uint64_t))
                {
                    fclose(f);
                    f = fopen(CHAIN_FILE, "r");
                    fc++;
                    if(fc > 333)
                    {
                        printf("\033[1m\x1B[31mERROR: fread() in getBalanceLocal() has failed.\x1B[0m\033[0m\n");
                        err++;
                        fclose(f);
                        return 0;
                    }
                    if(f == NULL)
                        continue;
                }

                if(tuid == uid)
                    return 0;
            }

            fclose(f);
        }
    }

    return 1;
}


//rExi check, last line of defense to prevent race conditions
//I cannot explain why the mutex seems to fail at times without
//this final check.
uint64_t uidlist[MAX_REXI_SIZE];
time_t uidtimes[MAX_REXI_SIZE];
uint rExi(uint64_t uid)
{
    int free = -1;
    for(uint i = 0; i < MAX_REXI_SIZE; i++)
    {
        if(uidlist[i] == uid)
            return 1;
        else if(time(0) > uidtimes[i] || uidtimes[i] == 0)
            free = i;
    }

    if(free != -1)
    {
        uidlist[free] = uid;
        uidtimes[free] = time(0) + 1;
    }

    return 0;
}

//Execute Transaction
int process_trans(const uint64_t uid, addr* from, addr* to, mval amount, sig* owner)
{
    //Do a quick unique check [realtime uid cache]
    if(has_uid(uid) == 1)
        return 0;
    add_uid(uid, 32400); //block uid for 9 hours (there can be collisions, as such it's a temporary block)

    //Create trans struct
    struct trans t;
    memset(&t, 0, sizeof(struct trans));
    t.uid = uid;
    memcpy(t.from.key, from->key, ECC_CURVE+1);
    memcpy(t.to.key, to->key, ECC_CURVE+1);
    t.amount = amount;
    
    //Lets verify if this signature is valid
    uint8_t thash[ECC_CURVE];
    makHash(thash, &t);
    if(ecdsa_verify(from->key, thash, owner->key) == 0)
    {
        //printf("\033[1m\x1B[31mERROR: verify failed.\x1B[0m\033[0m\n");
        return ERROR_SIGFAIL;
    }

    //Add the sig now we know it's valid
    memcpy(t.owner.key, owner->key, ECC_CURVE*2);


    //Check this address has the required value for the transaction (and that UID is actually unique)
    const int hbr = hasbalance(uid, from, amount);
    if(hbr == 0)
    {
        //printf("\033[1m\x1B[31mERROR: no balance.\x1B[0m\033[0m\n");
        return ERROR_NOFUNDS;
    }
    else if(hbr < 0)
    {
        //printf("\033[1m\x1B[31mERROR: uid exists.\x1B[0m\033[0m\n");
        return hbr; //it's an error code
    }


    //This check after the balance check as we need to verify transactions to self have the balance before confirming 'valid transaction'
    //which will cause the peers to index them, we don't want botnets loading into VFC. and making sure they have control of balance is
    //the best way to reduce this impact.
    if(memcmp(from->key, to->key, ECC_CURVE+1) != 0) //Only log if the user was not sending VFC to themselves.
    {

pthread_mutex_lock(&mutex3);

        //The mutex is not preventing race conditions, thats why we have the temporary 1 second expirary rExi / UID check in a limited size buffer. [has_uid()/add_uid() further protects from this condition]
        if(rExi(uid) == 0)
        {
            FILE* f = fopen(CHAIN_FILE, "a");
            if(f)
            {
                size_t written = 0;

                uint fc = 0;
                while(written == 0)
                {
                    written = fwrite(&t, 1, sizeof(struct trans), f);

                    // if(amount == 3)
                    //     printf("Special Written: %lu\n", uid);

                    fc++;
                    if(fc > 333)
                    {
                        printf("\033[1m\x1B[31mERROR: fwrite() in process_trans() has failed.\x1B[0m\033[0m\n");
                        err++;
                        fclose(f);
                        pthread_mutex_lock(&mutex3);
                        return ERROR_WRITE;
                    }
                    
                    if(written == 0)
                    {
                        fclose(f);
                        f = fopen(CHAIN_FILE, "a");
                        continue;
                    }
                    
                    //Did we corrupt the chain?
                    if(written < sizeof(struct trans))
                    {
                        fclose(f);

                        printf("\033[1m\x1B[31mERROR: fwrite() in process_trans() reverted potential chain corruption.\x1B[0m\033[0m\n");

                        //Revert the failed write
                        struct stat st;
                        stat(CHAIN_FILE, &st);
                        forceTruncate(CHAIN_FILE, st.st_size - written);

                        //Try again
                        written = 0;
                        f = fopen(CHAIN_FILE, "a");
                        continue;
                    }
                }

                fclose(f);
            }
        }

pthread_mutex_unlock(&mutex3);

    }
    

    //Success
    return 1;
}

void makAddrS(addr* pub, addr* priv)
{
    ecc_make_key(pub->key, priv->key);
}

void makAddr(addr* pub, addr* priv)
{
    //Make key pair
    ecc_make_key(pub->key, priv->key);

    //Dump Base58
    char bpub[MIN_LEN], bpriv[MIN_LEN];
    memset(bpub, 0, sizeof(bpub));
    memset(bpriv, 0, sizeof(bpriv));
    size_t len = MIN_LEN;
    b58enc(bpub, &len, pub->key, ECC_CURVE+1);
    b58enc(bpriv, &len, priv->key, ECC_CURVE);
    printf("\n\x1B[33mMade new Address / Key Pair\x1B[0m\n\nPublic: %s\n\nPrivate: %s\n\n\x1B[0m", bpub, bpriv);
}

void makGenesis()
{
    //Make genesis public key
    uint8_t gpub[ECC_CURVE+1];
    size_t len = ECC_CURVE+1;
    b58tobin(gpub, &len, "foxXshGUtLFD24G9pz48hRh3LWM58GXPYiRhNHUyZAPJ", 44);

    //Make Genesis Block (does not need to be signed or have src addr, or have a UID)
    struct trans t;
    memset(&t, 0, sizeof(struct trans));
    t.amount = 0xFFFFFFFF;
    memcpy(&t.to.key, gpub, ECC_CURVE+1);
    forceWrite(CHAIN_FILE, &t, sizeof(struct trans));
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Console & Socket I/O
*/

void savemem()
{
    FILE* f = fopen(".vfc/peers.mem", "w");
    if(f)
    {
        fwrite(peers, sizeof(uint), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen(".vfc/peers1.mem", "w");
    if(f)
    {
        fwrite(peer_tcount, sizeof(uint), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen(".vfc/peers2.mem", "w");
    if(f)
    {
        fwrite(peer_timeouts, sizeof(time_t), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen(".vfc/peers3.mem", "w");
    if(f)
    {
        fwrite(peer_ua, 64, MAX_PEERS, f);
        fclose(f);
    }
}

void loadmem()
{
    FILE* f = fopen(".vfc/peers.mem", "r");
    if(f)
    {
        if(fread(peers, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
        {
            printf("\033[1m\x1B[31mPeers Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
            err++;
        }
        fclose(f);
    }
    num_peers = countPeers();

    f = fopen(".vfc/peers1.mem", "r");
    if(f)
    {
        if(fread(peer_tcount, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
        {
            printf("\033[1m\x1B[31mPeers1 Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
            err++;
        }
        fclose(f);
    }

    f = fopen(".vfc/peers2.mem", "r");
    if(f)
    {
        if(fread(peer_timeouts, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
        {
            printf("\033[1m\x1B[31mPeers2 Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
            err++;
        }
        fclose(f);
    }

    f = fopen(".vfc/peers3.mem", "r");
    if(f)
    {
        if(fread(peer_ua, 64, MAX_PEERS, f) != MAX_PEERS)
        {
            printf("\033[1m\x1B[31mPeers3 Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
            err++;
        }
        fclose(f);
    }
}

void sigintHandler(int sig_num) 
{
    static int m_qe = 0;
    
    if(m_qe == 0)
    {
        printf("\n\x1B[33mPlease Wait while we save the peers state...\x1B[0m\n\n");
        m_qe = 1;

        savemem();
        exit(0);
    }
}

uint isNodeRunning()
{
    struct sockaddr_in server;

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(s == -1)
        return 0;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(gport);
    
    if(bind(s, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        close(s);
        return 1;
    }

    close(s);
    return 0;
}

void *processThread(void *arg)
{
    chdir(getHome());
    while(1)
    {
        //See if there is a new transaction to process
        struct trans t;
        uint32_t lip=0, lipo=0;
        unsigned char lreplay = 0;

pthread_mutex_lock(&mutex2);
        const int i = gQue();
        if(i == -1)
        {
            pthread_mutex_unlock(&mutex2);
            continue;
        }
        lreplay = replay[i];
        lip = ip[i];
        lipo = ipo[i];
        memcpy(&t, &tq[i], sizeof(struct trans));
        tq[i].amount = 0; //Signifies transaction as invalid / completed / processed (done)
pthread_mutex_unlock(&mutex2);

        //Process the transaction
        const int r = process_trans(t.uid, &t.from, &t.to, t.amount, &t.owner);

        //Good transaction!
        if(r == 1 && lreplay == 1)
        {
            //Track this client from origin
            addPeer(lip);
            if(lipo != 0)
                addPeer(lipo); //Track this client by attached origin

            //Construct a non-repeatable transaction and tell our peers
            const uint32_t origin = lip;
            const size_t len = 1+sizeof(uint64_t)+sizeof(uint32_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
            char pc[MIN_LEN];
            pc[0] = 't';
            char* ofs = pc + 1;
            memcpy(ofs, &origin, sizeof(uint32_t));
            ofs += sizeof(uint32_t);
            memcpy(ofs, &t.uid, sizeof(uint64_t));
            ofs += sizeof(uint64_t);
            memcpy(ofs, t.from.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, t.to.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, &t.amount, sizeof(mval));
            ofs += sizeof(mval);
            memcpy(ofs, t.owner.key, ECC_CURVE*2);
            triBroadcast(pc, len);
        }

    }
}

void *generalThread(void *arg)
{
    nice(3);
    chdir(getHome());
    time_t rs = time(0);
    time_t nr = time(0);
    time_t pr = time(0);
    time_t aa = time(0);
    while(1)
    {
        sleep(3);

        //Save memory state
        savemem();

        //Load new replay allow value
        forceRead(".vfc/rp.mem", &replay_allow, sizeof(uint)*6);

        //Let's execute a Sync every 9 mins
        if(time(0) > rs)
        {
            resyncBlocks();
            rs = time(0) + 540;
        }

        //Check which of the peers are still alive, those that are, update their timestamps
        if(time(0) > pr)
        {
            peersBroadcast(mid, 8);
            peersBroadcast("a", 1); //Give us your user-agent too please
            peer_timeouts[0] = time(0)+MAX_PEER_EXPIRE_SECONDS; //Reset master timeout
            pr = time(0) + PING_INTERVAL;
        }

        //Every hour have the rewards address send 1 vfc to itself to authorized any possible
        // new network addresses you may have been re-assigned.
        if(time(0) > aa)
        {
            char cmd[1024];
            sprintf(cmd, "vfc%s%s 0.001%s > /dev/null", myrewardkey, myrewardkey, myrewardkeyp);
            system(cmd);
            aa = time(0) + 3600; //every hour
        }
            
//This code is only for the masternode to execute, in-order to distribute rewards fairly.
#if MASTER_NODE == 1
        //Peers get a few chances to collect their reward
        if(rewardpaid == 0 && time(0) > nr)
        {
            csend(peers[rewardindex], "x", 1);
            nr = time(0)+1;
        }

        //Otherwise they forefit, it's time to reward the next peer.
        if(time(0) > nextreward)
        {
            //Set the next reward time / reset reward interval
            nextreward = time(0) + REWARD_INTERVAL;
            rewardpaid = 0;
            
            //Try to find a peer who has responded to a ping in atleast the last 9 minutes. Remember we check every peer with a ping every 3 minutes.
            rewardindex++;
            if(rewardindex >= num_peers) //Is the next peer valid?
            {
                rewardindex = 0; //Master is always worthy, never takes payments
            }
            else
            {
                //Is it ping worthy of a payment?
                uint dt = (time(0)-(peer_timeouts[rewardindex]-MAX_PEER_EXPIRE_SECONDS)); //Prevent negative numbers, causes wrap
                while(dt > PING_INTERVAL*4)
                {
                    rewardindex++;
                    if(rewardindex >= num_peers)
                    {
                        rewardindex = 0; //Master is always worthy, never takes payments
                        break;
                    }
                    else
                    {
                        dt = (time(0)-(peer_timeouts[rewardindex]-MAX_PEER_EXPIRE_SECONDS)); //for the while loop
                    }
                }
            }
            
        }
#endif
    }
}

uint64_t g_HSEC = 0;
void *miningThread(void *arg)
{
    chdir(getHome());
    nice(1); //Very high priority thread
    addr pub, priv;
    makAddrS(&pub, &priv);
    mval r = isSubGenesisAddressMine(pub.key); //cast
    uint64_t l = 0;
    time_t lt = time(0);
    time_t st = time(0) + 16;
    uint64_t stc = 0;
    while(1)
    {
        //Gen a new random addr
        makAddrS(&pub, &priv);
        r = isSubGenesisAddressMine(pub.key); //cast

        //Dump some rough h/s approximation
        if(time(0) > st)
        {
            time_t approx = (stc*nthreads);
            if(approx > 0)
                approx /= 16;

            g_HSEC = approx;

            stc = 0;
            st = time(0) + 16;
        }

        //Found subG?
        if(r > 0)
        {
            time_t d = time(0)-lt;
            if(d < 0)
                d = 0;

            //Convert to Base58
            char bpub[MIN_LEN], bpriv[MIN_LEN];
            memset(bpub, 0, sizeof(bpub));
            memset(bpriv, 0, sizeof(bpriv));
            size_t len = MIN_LEN;
            b58enc(bpub, &len, pub.key, ECC_CURVE+1);
            b58enc(bpriv, &len, priv.key, ECC_CURVE);

            //To console
            printf("\n\x1B[33mFound Sub-Genesis Address: \x1B[0m\nPublic: %s\nPrivate: %s\n\x1B[0m", bpub, bpriv);

            //Autoclaim
            pid_t fork_pid = fork();
            if(fork_pid == 0)
            {
                char cmd[1024];
                sprintf(cmd, "vfc %s%s %.3f %s > /dev/null", bpub, myrewardkey, toDB(r), bpriv);
                system(cmd);
                exit(0);
            }

            //Dump to file
            FILE* f = fopen(".vfc/minted.priv", "a");
            if(f != NULL)
            {
                flockfile(f); //lock

                fprintf(f, "%s (%.3f)\n", bpriv, toDB(r));

                funlockfile(f); //unlock
                fclose(f);
            }

            setlocale(LC_NUMERIC, "");
            time_t approx = (l*nthreads);
            if(approx > 0 && d > 0)
                approx /= d;
            printf("HASH/s: %'lu - Time Taken: %lu seconds\n\n\n", approx, d);
            l=0;
            lt = time(0);
        }

        l++;
        stc++;

    }
}





#if MASTER_NODE == 1
//This is a quick hackup for a function that scans through the whole local chain, and removes duplicates
//then saving the new chain to .vfc/cblocks.dat
void newClean()
{
    uint8_t gpub[ECC_CURVE+1];
    size_t len = ECC_CURVE+1;
    b58tobin(gpub, &len, "foxXshGUtLFD24G9pz48hRh3LWM58GXPYiRhNHUyZAPJ", 44);
    struct trans t;
    memset(&t, 0, sizeof(struct trans));
    t.amount = 0xFFFFFFFF;
    memcpy(&t.to.key, gpub, ECC_CURVE+1);
    FILE* f = fopen(".vfc/cblocks.dat", "w");
    if(f)
    {
        fwrite(&t, sizeof(struct trans), 1, f);
        fclose(f);
    }
}
void cleanChain()
{
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

            struct trans t;
            for(size_t i = 1; i < len; i += sizeof(struct trans))
            {
                //Copy transaction
                memcpy(&t, m+i, sizeof(struct trans));

                //Verify
                struct trans nt;
                memset(&nt, 0, sizeof(struct trans));
                nt.uid = t.uid;
                memcpy(nt.from.key, t.from.key, ECC_CURVE+1);
                memcpy(nt.to.key, t.to.key, ECC_CURVE+1);
                nt.amount = t.amount;
                uint8_t thash[ECC_CURVE];
                makHash(thash, &nt);
                if(ecdsa_verify(nt.from.key, thash, t.owner.key) == 0)
                {
                    printf("%lu: no verification\n", t.uid);
                    continue;
                }
                //
                
                //Check has balance and is unique
                int hbr = 0;
                int64_t rv = isSubGenesisAddress(t.from.key, 1);
                struct trans tn;
                for(size_t i = 0; i < len; i += sizeof(struct trans))
                {
                    if(tn.uid == t.uid)
                    {
                        hbr = ERROR_UIDEXIST;
                        break;
                    }
                    memcpy(&tn, m+i, sizeof(struct trans));

                    if(memcmp(&tn.to.key, &t.from.key, ECC_CURVE+1) == 0)
                        rv += tn.amount;
                    else if(memcmp(&tn.from.key, &t.from.key, ECC_CURVE+1) == 0)
                        rv -= tn.amount;
                }
                if(hbr != ERROR_UIDEXIST)
                {
                    if(rv >= t.amount)
                        hbr = 1;
                    else
                        hbr = 0;
                }
                if(hbr == 0)
                {
                    printf("%lu: no balance\n", t.uid);
                    continue;
                }
                else if(hbr < 0)
                {
                    printf("%lu uid exists\n", t.uid);
                    continue;
                }
                //

                //Ok let's write the transaction to chain
                if(memcmp(t.from.key, t.to.key, ECC_CURVE+1) != 0) //Only log if the user was not sending VFC to themselves.
                {
                    FILE* f = fopen(".vfc/cblocks.dat", "a");
                    if(f)
                    {
                        fwrite(&t, sizeof(struct trans), 1, f);
                        fclose(f);
                    }
                }
            }

            munmap(m, len);
        }

        close(f);
    }
}
#endif






int main(int argc , char *argv[])
{
    //Suppress Sigpipe
    signal(SIGPIPE, SIG_IGN);

    //set local working directory
    chdir(getHome());

    //Init arrays
    memset(&thread_ip, 0, sizeof(uint)*MAX_THREADS);
    memset(&tq, 0, sizeof(struct trans)*MAX_TRANS_QUEUE);
    memset(&ip, 0, sizeof(uint)*MAX_TRANS_QUEUE);
    memset(&ipo, 0, sizeof(uint)*MAX_TRANS_QUEUE);
    memset(&replay, 0, sizeof(unsigned char)*MAX_TRANS_QUEUE);
    memset(&delta, 0, sizeof(time_t)*MAX_TRANS_QUEUE);

    memset(&uidlist, 0, sizeof(uint64_t)*MIN_LEN);
    memset(&uidtimes, 0, sizeof(time_t)*MIN_LEN);
    // < Peer arrays do not need initilisation >

    //Init UID hashmap
    init_sites();

    //Workout size of server for replay scaling
    nthreads = get_nprocs();
    if(nthreads > 2)
        MAX_THREADS = 8*(nthreads-2);
    if(MAX_THREADS > MAX_THREADS_BUFF)
        MAX_THREADS = MAX_THREADS_BUFF;

    //create vfc dir
#if RUN_AS_ROOT == 1
    mkdir(".vfc", 0777);
#else
    mkdir(".vfc", 0700);
#endif

    //Create rewards address if it doesnt exist
    if(access(".vfc/public.key", F_OK) == -1)
    {
        addr pub, priv;
        makAddr(&pub, &priv);

        char bpub[MIN_LEN], bpriv[MIN_LEN];
        memset(bpub, 0, sizeof(bpub));
        memset(bpriv, 0, sizeof(bpriv));
        size_t len = MIN_LEN;
        b58enc(bpub, &len, pub.key, ECC_CURVE+1);
        b58enc(bpriv, &len, priv.key, ECC_CURVE);

        FILE* f = fopen(".vfc/public.key", "w");
        if(f)
        {
            fwrite(bpub, sizeof(char), strlen(bpub), f);
            fclose(f);
        }
        f = fopen(".vfc/private.key", "w");
        if(f)
        {
            fwrite(bpriv, sizeof(char), strlen(bpriv), f);
            fclose(f);
        }
    }

    //Load your public key for rewards
    FILE* f = fopen(".vfc/public.key", "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);
        fseek(f, 0, SEEK_SET);

        memset(myrewardkey, 0x00, sizeof(myrewardkey));
        myrewardkey[0] = ' ';
        
        if(fread(myrewardkey+1, sizeof(char), len, f) != len)
            printf("\033[1m\x1B[31mFailed to load Rewards address, this means you are unable to receive rewards.\x1B[0m\033[0m\n");

        //clean off any new spaces at the end, etc
        const int sal = strlen(myrewardkey);
        for(int i = 1; i < sal; ++i)
            if(isalonu(myrewardkey[i]) == 0)
                myrewardkey[i] = 0x00;

        fclose(f);
    }
    f = fopen(".vfc/private.key", "r"); //and private key for auto-auth
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);
        fseek(f, 0, SEEK_SET);

        memset(myrewardkeyp, 0x00, sizeof(myrewardkeyp));
        myrewardkeyp[0] = ' ';
        
        if(fread(myrewardkeyp+1, sizeof(char), len, f) != len)
            printf("\033[1m\x1B[31mFailed to load Rewards address private key, automatic network authentication will no longer be operational.\x1B[0m\033[0m\n");

        //clean off any new spaces at the end, etc
        const int sal = strlen(myrewardkeyp);
        for(int i = 1; i < sal; ++i)
            if(isalonu(myrewardkeyp[i]) == 0)
                myrewardkeyp[i] = 0x00;

        fclose(f);
    }

    //Set genesis public key
    size_t len = ECC_CURVE+1;
    b58tobin(genesis_pub, &len, "foxXshGUtLFD24G9pz48hRh3LWM58GXPYiRhNHUyZAPJ", 44);

    //Set next reward time
#if MASTER_NODE == 1
    nextreward = time(0) + REWARD_INTERVAL;
#endif

    //Set the MID
    mid[0] = '\t';
    mid[1] = qRand(0, 255);
    mid[2] = qRand(0, 255);
    mid[3] = qRand(0, 255);
    mid[4] = qRand(0, 255);
    mid[5] = qRand(0, 255);
    mid[6] = qRand(0, 255);
    mid[7] = qRand(0, 255);

    //quick send
    if(argc == 4)
    {
        if(strcmp(argv[1], "qsend") == 0)
        {
            char cmd[1024];
            sprintf(cmd, "vfc%s %s %.3f%s", myrewardkey, argv[3], atof(argv[2]), myrewardkeyp);
            system(cmd);
            
            exit(0);
        }
    }

    //Outgoings and Incomings
    if(argc == 3)
    {
        //Mine VFC
        if(strcmp(argv[1], "mine") == 0)
        {
            printf("\033[H\033[J");

            nthreads = atoi(argv[2]);
            printf("\x1B[33m%i Threads\x1B[0m launched..\nMining Difficulty: \x1B[33m%.2f\x1B[0m\nSaving mined private keys to .vfc/minted.priv\n\nMining please wait...\n\n", nthreads, getMiningDifficulty());

            //Launch mining threads
            for(int i = 0; i < nthreads; i++)
            {
                pthread_t tid;
                if(pthread_create(&tid, NULL, miningThread, NULL) != 0)
                    continue;
            }

            //Loop with 3 sec console output delay
            while(1)
            {
                sleep(16);

                if(g_HSEC == 0)
                    continue;

                setlocale(LC_NUMERIC, "");
                if(g_HSEC < 1000)
                    printf("HASH/s: %'lu\n", g_HSEC);
                else if(g_HSEC < 1000000)
                    printf("kH/s: %.2f\n", (double)g_HSEC / 1000);
                else if(g_HSEC < 1000000000)
                    printf("mH/s: %.2f\n", (double)g_HSEC / 1000000);
            }
            
            //only exits on sigterm
            exit(0);
        }

        if(strcmp(argv[1], "getpub") == 0)
        {
            //Force console to clear.
            printf("\033[H\033[J");

            //Get Private Key
            uint8_t p_privateKey[ECC_BYTES+1];
            size_t len = ECC_CURVE;
            b58tobin(p_privateKey, &len, argv[2], strlen(argv[2]));

            //Gen Public Key
            uint8_t p_publicKey[ECC_BYTES+1];
            ecc_get_pubkey(p_publicKey, p_privateKey);

            //Dump Public Key as Base58
            char bpub[MIN_LEN];
            memset(bpub, 0, sizeof(bpub));
            len = MIN_LEN;
            b58enc(bpub, &len, p_publicKey, ECC_CURVE+1);

            printf("\n\x1B[33mPublic Key Generated\x1B[0m\n\nPublic: %s\n\n\x1B[0m", bpub);
            
            exit(0);
        }

        //truncate blocks file at first invalid transaction found
        if(strcmp(argv[1], "trunc") == 0)
        {
            truncate_at_error(CHAIN_FILE, atoi(argv[2]));
            exit(0);
        }

        if(strcmp(argv[1], "issub") == 0)
        {
            //Get Public Key
            uint8_t p_publicKey[ECC_BYTES+1];
            size_t len = ECC_CURVE;
            b58tobin(p_publicKey, &len, argv[2], strlen(argv[2]));

            //Dump Public Key as Base58
            const uint64_t v = isSubGenesisAddress(p_publicKey, 1);
            if(v > 0)
                printf("\n\x1B[33msubG: \x1B[0m %lu\n\n\x1B[0m", v);
            else
                printf("\033[1m\x1B[31mThis is not a subGenesis (subG) Address.\x1B[0m\033[0m\n");
            
            exit(0);
        }

        if(strcmp(argv[1], "addpeer") == 0)
        {
            loadmem();
            addPeer(inet_addr(argv[2]));
            printf("\nThank you peer %s has been added to your peer list. Please restart your full node process to load the changes.\n\n", argv[2]);
            savemem();
            exit(0);
        }

        if(strstr(argv[1], "in") != NULL)
        {
            addr a;
            size_t len = ECC_CURVE+1;
            b58tobin(a.key, &len, argv[2], strlen(argv[2]));
            printIns(&a);
            exit(0);
        }

        if(strstr(argv[1], "out") != NULL)
        {
            addr a;
            size_t len = ECC_CURVE+1;
            b58tobin(a.key, &len, argv[2], strlen(argv[2]));
            printOuts(&a);
            exit(0);
        }
    }

    //Some basic funcs
    if(argc == 2)
    {
        //Help
        if(strcmp(argv[1], "help") == 0)
        {
            printf("\n\x1B[33mTo update your client use:\x1B[0m\n ./vfc update\n\n");
            printf("\x1B[33mTo get an address balance use:\x1B[0m\n ./vfc <address public key>\n\n");
            printf("\x1B[33mTo check sent transactions from an address use:\x1B[0m\n ./vfc out <address public key>\n\n");
            printf("\x1B[33mTo check received transactions from an address use:\x1B[0m\n ./vfc in <address public key>\n\n");
            printf("\x1B[33mTo make a transaction use:\x1B[0m\n ./vfc <sender public key> <reciever public key> <amount> <sender private key>\x1B[0m\n\n");
            printf("\x1B[33mTo make a transaction from your rewards address use:\x1B[0m\n ./vfc qsend <amount> <receiver address>\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain resync use:\x1B[0m\n ./vfc resync\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain resync only from the master use:\x1B[0m\n ./vfc master_resync\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain sync use:\x1B[0m\n ./vfc sync\x1B[0m\n\n");
            printf("\x1B[33mCPU mining of VFC:\x1B[0m\n ./vfc mine <num-threads>\n\n");
            printf("\x1B[33mTo create a new Address, Public / Private Key-Pair:\x1B[0m\n ./vfc new\x1B[0m\n\n");
            printf("\x1B[33mGet Public Key from Private Key:\x1B[0m\n ./vfc getpub <private key>\x1B[0m\n\n");
            printf("\x1B[33mTo manually add a peer use:\x1B[0m\n ./vfc addpeer <peer ip-address>\n\n");
            printf("\x1B[33mList all locally indexed peers and info:\x1B[0m\n ./vfc peers\n\n");
            printf("\x1B[33mDump all transactions in the blockchain:\x1B[0m\n ./vfc dump\n\n");
            printf("\x1B[33mDump all double spend transactions detected from other peers:\x1B[0m\n ./vfc dumpbad\n\n");
            printf("\x1B[33mClear all double spend transactions detected from other peers:\x1B[0m\n ./vfc clearbad\n\n");
            printf("\x1B[33mReturns your Public Key stored in ~/.vfc/public.key for reward collections:\x1B[0m\n ./vfc reward\n\n");
            printf("\x1B[33mReturns client version:\x1B[0m\n ./vfc version\n\n");
            printf("\x1B[33mReturns client blocks.dat size / num transactions:\x1B[0m\n ./vfc heigh\n\n");
            printf("\x1B[33mReturns the circulating supply:\x1B[0m\n ./vfc circulating\n\n");
            printf("\x1B[33mReturns the mined supply:\x1B[0m\n ./vfc mined\n\n");
            printf("\x1B[33mReturns the mining difficulty:\x1B[0m\n ./vfc difficulty\n\n");
            printf("\x1B[33mCheck's if supplied address is subG, if so returns value of subG address:\x1B[0m\n ./vfc issub <public key>\n\n");
            printf("\x1B[33mDoes it look like this client wont send transactions? Maybe the master server is offline and you have no saved peers, if so then scan for a peer using the following command:\x1B[0m\n ./vfc scan\x1B[0m\n\n");
            printf("\x1B[33mScan blocks.dat for invalid transactions and truncate at first invalid transaction:\x1B[0m\n ./vfc trunc <offset x transactions>\n\n");
            printf("\x1B[33mScan blocks.dat for invalid transactions and generated a cleaned version in the same directory called cblocks.dat:\x1B[0m\n ./vfc clean\n\n");
            
            printf("\x1B[33mTo get started running a dedicated node, execute ./vfc on a seperate screen, you will need to make atleast one transaction a month to be indexed by the network.\x1B[0m\n\n");
            exit(0);
        }

        //get mining difficulty
        if(strcmp(argv[1], "difficulty") == 0)
        {
            printf("%.3f\n", getMiningDifficulty());
            exit(0);
        }

        //circulating supply
        if(strcmp(argv[1], "circulating") == 0)
        {
            printf("%.3f\n", toDB(getCirculatingSupply()));
            exit(0);
        }

        //Mined VFC in circulation
        if(strcmp(argv[1], "mined") == 0)
        {
            printf("%.3f\n", toDB(getMinedSupply()));
            exit(0);
        }

        //version
        if(strcmp(argv[1], "version") == 0)
        {
            printf("\x1B[33m%s\x1B[0m\n", version);
            exit(0);
        }

        //Updates installed client from official git
        if(strcmp(argv[1], "update") == 0)
        {
            printf("Please run this command with sudo or sudo -s, aka sudo vfc update\n");
            system("rm -r VFC-Core");
            system("git clone https://github.com/vfcash/VFC-Core");
            chdir("VFC-Core");
            system("chmod 0777 compile.sh");
            system("./compile.sh");
            exit(0);
        }

        //Block height / total blocks / size
        if(strcmp(argv[1], "heigh") == 0)
        {
            struct stat st;
            stat(CHAIN_FILE, &st);
            if(st.st_size > 0)
                printf("\x1B[33m%1.f\x1B[0m kb / \x1B[33m%u\x1B[0m Transactions\n", (double)st.st_size / 1000, (uint)st.st_size / 144);
            exit(0);
        }

        //Mine VFC
        if(strcmp(argv[1], "mine") == 0)
        {
            printf("\033[H\033[J");

            nthreads = get_nprocs();
            printf("\x1B[33m%i CPU\x1B[0m Cores detected..\nMining Difficulty: \x1B[33m%.2f\x1B[0m\nSaving mined private keys to .vfc/minted.priv\n\nMining please wait...\n\n", nthreads, getMiningDifficulty());
            

            //Launch mining threads
            for(int i = 0; i < nthreads; i++)
            {
                pthread_t tid;
                if(pthread_create(&tid, NULL, miningThread, NULL) != 0)
                    continue;
            }

            //Loop with 3 sec console output delay
            while(1)
            {
                sleep(16);

                if(g_HSEC == 0)
                    continue;

                setlocale(LC_NUMERIC, "");
                if(g_HSEC < 1000)
                    printf("HASH/s: %'lu\n", g_HSEC);
                else if(g_HSEC < 1000000)
                    printf("kH/s: %.2f\n", (double)g_HSEC / 1000);
                else if(g_HSEC < 1000000000)
                    printf("mH/s: %.2f\n", (double)g_HSEC / 1000000);
            }
            
            //only exits on sigterm
            exit(0);
        }

        //sync
        if(strcmp(argv[1], "sync") == 0)
        {
            setMasterNode();
            loadmem();
            resyncBlocks();
            
            __off_t ls = 0;
            uint tc = 0;
            while(1)
            {
                printf("\033[H\033[J");
                if(tc >= 4)
                {
                    tc = 0;
                    resyncBlocks(); //Sync from a new random peer if no data after x seconds
                }
                struct stat st;
                stat(CHAIN_FILE, &st);
                if(st.st_size != ls)
                {
                    ls = st.st_size;
                    tc = 0;
                }
    
                struct in_addr i1;
                i1.s_addr = replay_allow[0];
                struct in_addr i2;
                i2.s_addr = replay_allow[1];
                struct in_addr i3;
                i3.s_addr = replay_allow[2];
                struct in_addr i4;
                i4.s_addr = replay_allow[3];
                struct in_addr i5;
                i5.s_addr = replay_allow[4];
                struct in_addr i6;
                i6.s_addr = replay_allow[5];

                forceWrite(".vfc/rp.mem", &replay_allow, sizeof(uint)*6);
                forceRead(".vfc/rph.mem", &replay_height, sizeof(uint));

                if(replay_allow[0] == 0)
                    printf("\x1B[33m%.1f\x1B[0m kb of \x1B[33m%.1f\x1B[0m kb downloaded press CTRL+C to Quit. Synchronizing only from the Master.\n", (double)st.st_size / 1000, (double)replay_height / 1000);
                else
                {
                    printf("\x1B[33m%.1f\x1B[0m kb of \x1B[33m%.1f\x1B[0m kb downloaded press CTRL+C to Quit. Authorized Peer: %s / ", (double)st.st_size / 1000, (double)replay_height / 1000, inet_ntoa(i1));
                    printf("%s / ", inet_ntoa(i2));
                    printf("%s / ", inet_ntoa(i3));
                    printf("%s / ", inet_ntoa(i4));
                    printf("%s / ", inet_ntoa(i5));
                    printf("%s.\n", inet_ntoa(i6));
                }
                tc++;
                sleep(1);
            }

            exit(0);
        }

        //master_resync
        if(strcmp(argv[1], "master_resync") == 0)
        {
            remove("blocks.dat");
            system("wget -O.vfc/master_blocks.dat http://46.4.183.153/blocks.dat");
            system("cp .vfc/master_blocks.dat .vfc/blocks.dat");
            printf("\x1B[33mResync from master complete.\x1B[0m\n\n");
            exit(0);
        }

        //resync
        if(strcmp(argv[1], "resync") == 0)
        {
            makGenesis(); //Erases chain and resets it for a full resync
            setMasterNode();
            loadmem();
            resyncBlocks();
            forceWrite(".vfc/rp.mem", &replay_allow, sizeof(uint)*6);
            printf("\x1B[33mResync Executed.\x1B[0m\n\n");
            exit(0);
        }

        //Gen new address
        if(strcmp(argv[1], "new") == 0)
        {
            addr pub, priv;
            makAddr(&pub, &priv);
            exit(0);
        }

        //Scan for peers
        if(strcmp(argv[1], "scan") == 0)
        {
            loadmem();
            scanPeers();
            savemem();
            exit(0);
        }

        //Dump all trans
        if(strcmp(argv[1], "dump") == 0)
        {
            dumptrans();
            exit(0);
        }

        //Dump all bad trans
        if(strcmp(argv[1], "dumpbad") == 0)
        {
            dumpbadtrans();
            exit(0);
        }

        //Clear all bad trans
        if(strcmp(argv[1], "clearbad") == 0)
        {
            remove(BADCHAIN_FILE);
            exit(0);
        }

        //Create a cleaned chain
        if(strcmp(argv[1], "clean") == 0)
        {
            newClean();
            cleanChain();
            exit(0);
        }

        //Return reward addr
        if(strcmp(argv[1], "reward") == 0)
        {
            loadmem();

            addr rk;
            size_t len = ECC_CURVE+1;
            b58tobin(rk.key, &len, myrewardkey+1, strlen(myrewardkey)-1); //It's got a space in it (at the beginning) ;)
            printf("Please Wait...\n");
            
            uint64_t bal = getBalance(&rk);
            uint64_t baln = 0;
            uint64_t balt = 0;
            sleep(3);
            forceRead(".vfc/bal.mem", &baln, sizeof(uint64_t));
            forceRead(".vfc/balt.mem", &balt, sizeof(uint64_t));

            uint64_t fbal = bal;
            if(balt > fbal)
                fbal = balt;

#if MASTER_NODE == 1
            fbal = bal;
#endif

            setlocale(LC_NUMERIC, "");
            printf("\x1B[33m(Local Balance / Mode Network Balance / Highest Network Balance)\x1B[0m\n");
            printf("\x1B[33mYour reward address is:\x1B[0m%s\n(\x1B[33m%'.3f VFC\x1B[0m / \x1B[33m%'.3f VFC\x1B[0m / \x1B[33m%'.3f VFC\x1B[0m)\n\n\x1B[33mFinal Balance:\x1B[0m %'.3f VFC\n\n", myrewardkey, toDB(bal), toDB(balt), toDB(baln), toDB(fbal));
            exit(0);
        }

        //Force add a peer
        if(strcmp(argv[1], "addpeer") == 0)
        {
            loadmem();
            printf("\x1B[33mPlease input Peer IP Address: \x1B[0m");
            char in[32];
            fgets(in, 32, stdin);
            addPeer(inet_addr(in));
            printf("\nThank you peer %s has been added to your peer list. Please restart your full node process to load the changes.\n\n", in);
            savemem();
            exit(0);
        }

        //List all peers and their total throughput
        if(strcmp(argv[1], "peers") == 0)
        {
            loadmem();
            printf("\n\x1B[33mTip; If you are running a full-node then consider hosting a website on port 80 where you can declare a little about your operation and a VFC address people can use to donate to you on. Thus you should be able to visit any of these IP addresses in a web-browser and find out a little about each node or obtain a VFC Address to donate to the node operator on.\x1B[0m\n\n");
            printf("\x1B[33mTotal Peers:\x1B[0m %u\x1B[33\n\n", num_peers);
            printf("\x1B[33mIP Address / Number of Transactions Relayed / Seconds since last trans or ping / user-agent [version/blockheight/nodename/machine] \x1B[0m\n");
            uint ac = 0;
            for(uint i = 0; i < num_peers; ++i)
            {
                struct in_addr ip_addr;
                ip_addr.s_addr = peers[i];
                const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS); //ping delta
                if(pd <= PING_INTERVAL*4)
                {
                    printf("%s / %u / %u / %s\n", inet_ntoa(ip_addr), peer_tcount[i], pd, peer_ua[i]);
                    ac++;
                }
            }
            printf("\x1B[33mAlive Peers:\x1B[0m %u\n\n", ac);
            // printf("\n--- Possibly Dead Peers ---\n\n");
            // uint dc = 0;
            // for(uint i = 0; i < num_peers; ++i)
            // {
            //     struct in_addr ip_addr;
            //     ip_addr.s_addr = peers[i];
            //     const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS); //ping delta
            //     if(pd > PING_INTERVAL*4)
            //     {
            //         printf("%s / %u / %u / %s\n", inet_ntoa(ip_addr), peer_tcount[i], pd, peer_ua[i]);
            //         dc++;
            //     }
            // }
            // printf("\x1B[33mDead Peers:\x1B[0m %u\n\n", dc);
            exit(0);
        }
    }

    //Let's make sure we're on the correct chain
    if(verifyChain(CHAIN_FILE) == 0)
    {
        printf("\033[1m\x1B[31mSorry you're not on the right chain. Please resync by running ./vfc resync or for a faster resync try ./vfc master_resync\x1B[0m\033[0m\n\n");
        system("vfc master_resync");
        exit(0);
    }

    //Set Master Node
    setMasterNode();

    //Load Mem
    loadmem();

    //Does user just wish to get address balance?
    if(argc == 2)
    {
        if(isNodeRunning() == 0)
        {
            printf("\033[1m\x1B[31mPlease make sure you are running the full node and that you have synchronized to the latest blockchain before checking an address balance.\x1B[0m\033[0m\n\n");
            exit(0);
        }

        //Get balance
        addr from;
        size_t len = ECC_CURVE+1;
        b58tobin(from.key, &len, argv[1], strlen(argv[1]));
        printf("Please Wait...\n");

        //Local
        struct timespec s;
        clock_gettime(CLOCK_MONOTONIC, &s);
        uint64_t bal = getBalance(&from);
        struct timespec e;
        clock_gettime(CLOCK_MONOTONIC, &e);
        time_t td = (e.tv_nsec - s.tv_nsec);
        if(td > 0){td /= 1000000;}
        else if(td < 0){td = 0;}

        //Network
        uint64_t baln = 0, balt = 0;
#if MASTER_NODE == 0
        sleep(3);
#endif
        forceRead(".vfc/bal.mem", &baln, sizeof(uint64_t));
        forceRead(".vfc/balt.mem", &balt, sizeof(uint64_t));

        uint64_t fbal = bal;
        if(balt > fbal)
            fbal = balt;

#if MASTER_NODE == 1
        fbal = bal;
#endif
        
        setlocale(LC_NUMERIC, "");
        printf("\x1B[33m(Local Balance / Mode Network Balance / Highest Network Balance)\x1B[0m\n");
        printf("\x1B[33mThe Balance for Address: \x1B[0m%s\n(\x1B[33m%'.3f VFC\x1B[0m / \x1B[33m%'.3f VFC\x1B[0m / \x1B[33m%'.3f VFC\x1B[0m)\n\x1B[33mTime Taken\x1B[0m %li \x1B[33mMilliseconds (\x1B[0m%li ns\x1B[33m).\x1B[0m\n\n\x1B[33mFinal Balance:\x1B[0m %'.3f VFC\n\n", argv[1], toDB(bal), toDB(balt), toDB(baln), td, (e.tv_nsec - s.tv_nsec), toDB(fbal));
        exit(0);
    }

    //Does user just wish to execute transaction?
    if(argc == 5)
    {
    //Force console to clear.
    printf("\033[H\033[J");

        if(isNodeRunning() == 0)
        {
            printf("\033[1m\x1B[31mPlease make sure you are running the full node and that you have synchronized to the latest blockchain before making a transaction.\x1B[0m\033[0m\n\n");
            exit(0);
        }

        //Recover data from parameters
        uint8_t from[ECC_CURVE+1];
        uint8_t to[ECC_CURVE+1];
        uint8_t priv[ECC_CURVE];
        //
        size_t blen = ECC_CURVE+1;
        b58tobin(from, &blen, argv[1], strlen(argv[1]));
        b58tobin(to, &blen, argv[2], strlen(argv[2]));
        blen = ECC_CURVE;
        b58tobin(priv, &blen, argv[4], strlen(argv[4]));

        const mval sbal = fromDB(atof(argv[3]));
        
        //Construct Transaction
        struct trans t;
        memset(&t, 0, sizeof(struct trans));
        //
        memcpy(t.from.key, from, ECC_CURVE+1);
        memcpy(t.to.key, to, ECC_CURVE+1);
        t.amount = sbal;

        //Too low amount?
        if(t.amount < 0.001)
        {
            printf("\033[1m\x1B[31mSorry the amount you provided was too low, please try 0.001 VFC or above.\x1B[0m\033[0m\n\n");
            exit(0);
        }

    //Get balance..
    const int64_t bal0 = getBalanceLocal(&t.from);

        //UID Based on timestamp & signature
        time_t ltime = time(NULL);
        char suid[MIN_LEN];
        snprintf(suid, sizeof(suid), "%s/%s", asctime(localtime(&ltime)), argv[1]); //timestamp + base58 from public key
        t.uid = crc64(0, suid, strlen(suid));

        //Sign the block
        uint8_t thash[ECC_CURVE];
        makHash(thash, &t);
        if(ecdsa_sign(priv, thash, t.owner.key) == 0)
        {
            printf("\n\033[1m\x1B[31mSorry you're client failed to sign the Transaction.\x1B[0m\033[0m\n\n");
            exit(0);
        }

        //Generate Packet (pc)
        const uint origin = 0;
        size_t len = 1+sizeof(uint)+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        char pc[MIN_LEN];
        pc[0] = 't';
        char* ofs = pc + 1;
        memcpy(ofs, &origin, sizeof(uint));
        ofs += sizeof(uint);
        memcpy(ofs, &t.uid, sizeof(uint64_t));
        ofs += sizeof(uint64_t);
        memcpy(ofs, from, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, to, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, &t.amount, sizeof(mval));
        ofs += sizeof(mval);
        memcpy(ofs, t.owner.key, ECC_CURVE*2);

        //Broadcast
        sendMaster(pc, len);
        peersBroadcast(pc, len);

#if MASTER_NODE == 1
        //Send locally as a replay
        len = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        pc[0] = 'p'; //This is a re*P*lay
        ofs = pc + 1;
        memcpy(ofs, &t.uid, sizeof(uint64_t));
        ofs += sizeof(uint64_t);
        memcpy(ofs, t.from.key, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, t.to.key, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, &t.amount, sizeof(mval));
        ofs += sizeof(mval);
        memcpy(ofs, t.owner.key, ECC_CURVE*2);
        csend(inet_addr("127.0.0.1"), pc, len);
#endif

        //Log
        char howner[MIN_LEN];
        memset(howner, 0, sizeof(howner));
        size_t zlen = MIN_LEN;
        b58enc(howner, &zlen, t.owner.key, ECC_CURVE);

        printf("\n\x1B[33mPacket Size: %lu. %'.3f VFC. Sending Transaction...\x1B[0m\n", len, (double)t.amount / 1000);
        printf("\033[1m\x1B[31m%s > %s : %u : %s\x1B[0m\033[0m\n", argv[1], argv[2], t.amount, howner);
        printf("\x1B[33mTransaction Sent.\x1B[0m\n\n");

    //Get balance again..
#if MASTER_NODE == 1
    sleep(3);
#else
    sleep(6);
#endif

    const int64_t bal1 = getBalanceLocal(&t.from);
    setlocale(LC_NUMERIC, "");
    if(bal0-bal1 <= 0)
        printf("\033[1m\x1B[31mTransaction Sent, but unable to verify it's success. Refer to sent transactions for confirmation.\x1B[0m\033[0m\n\n");
    else
        printf("\x1B[33mVFC Sent: \x1B[0m%'.3f VFC\n\n", toDB(bal0-bal1));

        //Done
        exit(0);
    }

    //How did we get here?
    if(argc > 1)
    {
        //Looks like some unknown command was executed.
        printf("Command not recognised.\n");
        exit(0);
    }

    //Don't run a node twice
    if(isNodeRunning() == 1)
    {
        printf("\033[1m\x1B[31mThe VFC node is already running.\x1B[0m\033[0m\n\n");
        exit(0);
    }

    //Check for broken blocks
    printf("Quick Scan: Checking blocks.dat for invalid transactions...\n");
    truncate_at_error(CHAIN_FILE, 33333);

    //Hijack CTRL+C
    signal(SIGINT, sigintHandler);

    //is x86_64? only use mmap on x86_64
    struct utsname ud;
    uname(&ud);
    if(strcmp(ud.machine, "x86_64") != 0)
    {
        is8664 = 0;
        printf("\033[1m\x1B[31mRunning without mmap() as system is not x86_64.\x1B[0m\033[0m\n\n");
    }
    
    //Launch Info
    timestamp();
    printf("\n\x1B[33m.. VFC ..\n");
    printf("https://VF.CASH - https://VFCASH.UK\n");
    printf("https://github.com/vfcash\n");
    printf("v%s\x1B[0m\n\n", version);
    printf("\x1B[33mYou will have to make a transaction before your IPv4 address registers\nwith the mainnet when running a full time node/daemon.\x1B[0m\n\n");
    printf("\x1B[33mTo get a full command list use:\x1B[0m\n ./vfc help\n\n");
    char cwd[MIN_LEN];
    getcwd(cwd, sizeof(cwd));
    printf("Current Directory: %s\n\n", cwd);

    //Launch the Transaction Processing thread
    nthreads = get_nprocs();
    for(int i = 0; i < nthreads; i++)
    {
        pthread_t tid;
        if(pthread_create(&tid, NULL, processThread, NULL) != 0)
            continue;
    }

    //Launch the General Processing thread
    pthread_t tid2;
    pthread_create(&tid2, NULL, generalThread, NULL);
	
    //Sync Blocks
    resyncBlocks();
     
    //Loop, until sigterm
    while(1)
    {
        //Vars
        struct sockaddr_in server, client;
        uint slen = sizeof(client);

        //Create socket
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(s == -1)
        {
            printf("\033[1m\x1B[31mFailed to create write socket ...\x1B[0m\033[0m\n");
            sleep(3);
            continue;
        }

        //Prepare the sockaddr_in structure
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(gport);
        
        //Bind port to socket
        if(bind(s, (struct sockaddr*)&server, sizeof(server)) < 0)
        {
            printf("\033[1m\x1B[31mSorry the port %u seems to already be in use. Daemon must already be running, good bye.\x1B[0m\033[0m\n\n", gport);
            exit(0);
        }
        printf("Waiting for connections...\n\n");

        //Never allow process to end
        uint reqs = 0;
        time_t st = time(0);
        time_t tt = time(0);
        int read_size;
        char rb[RECV_BUFF_SIZE];
        uint rsi = 0;
        const uint trans_size = 1+sizeof(uint)+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        const uint replay_size = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        while(1)
        {
            //Client Command
            memset(rb, 0, sizeof(rb));
            read_size = recvfrom(s, rb, RECV_BUFF_SIZE-1, 0, (struct sockaddr *)&client, &slen);
            reqs++;

            //Are we the same node sending to itself, if so, ignore.
            //if(server.sin_addr.s_addr == client.sin_addr.s_addr) //I know, this is very rarily ever effective. If ever.
                //continue;

            //It's time to payout some rewards (if eligible).
#if MASTER_NODE == 1
            if(rb[0] == ' ')
            {
                RewardPeer(client.sin_addr.s_addr, rb); //Check if the peer is eligible
            }
#endif

            //peer has sent a live or dead transaction
            if((rb[0] == 't' || rb[0] == 'd') && read_size == trans_size)
            {
                //Root origin peer address
                uint origin = 0;

                //Decode packet into a Transaction & Origin
                struct trans t;
                memset(&t, 0, sizeof(struct trans));
                char* ofs = rb+1;
                memcpy(&origin, ofs, sizeof(uint)); //grab root origin address
                ofs += sizeof(uint);
                memcpy(&t.uid, ofs, sizeof(uint64_t)); //grab uid
                ofs += sizeof(uint64_t);
                memcpy(t.from.key, ofs, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(t.to.key, ofs, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(&t.amount, ofs, sizeof(mval));
                ofs += sizeof(mval);
                memcpy(t.owner.key, ofs, ECC_CURVE*2);

                //Process Transaction (Threaded (using processThread()) not to jam up UDP relay)
                if(aQue(&t, client.sin_addr.s_addr, origin, 1) == 1)
                {
                    //printf("Q: %u %lu %u\n", t.amount, t.uid, gQueSize());

                    //Broadcast to peers
                    origin = client.sin_addr.s_addr;
                    char pc[MIN_LEN];
                    pc[0] = 'd';
                    char* ofs = pc + 1;
                    memcpy(ofs, &origin, sizeof(uint));
                    ofs += sizeof(uint);
                    memcpy(ofs, &t.uid, sizeof(uint64_t));
                    ofs += sizeof(uint64_t);
                    memcpy(ofs, t.from.key, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(ofs, t.to.key, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(ofs, &t.amount, sizeof(mval));
                    ofs += sizeof(mval);
                    memcpy(ofs, t.owner.key, ECC_CURVE*2);
                    triBroadcast(pc, trans_size);
                }
            }

            //peer is requesting a block replay
            else if(rb[0] == 'r' && read_size == 1)
            {
                //Is this peer even registered? if not, suspect foul play, not part of verified network.
                if(isPeer(client.sin_addr.s_addr) == 1)
                {
                    //Launch replay
                    launchReplayThread(client.sin_addr.s_addr);
                }
            }

            //peer is requesting your user agent
            else if(rb[0] == 'a' && rb[1] == 0x00 && read_size == 1)
            {
                //Check this is the replay peer
                if(isPeer(client.sin_addr.s_addr))
                {
                    struct stat st;
                    stat(CHAIN_FILE, &st);

                    struct utsname ud;
                    uname(&ud);

                    char pc[MIN_LEN];
                    snprintf(pc, sizeof(pc), "a%s, %u, %s, %s", version, (uint)st.st_size / 133, ud.nodename, ud.machine);

                    csend(client.sin_addr.s_addr, pc, strlen(pc));
                }
            }

            //peer is sending it's user agent
            else if(rb[0] == 'a')
            {
                //Check this is a peer
                const int p = getPeer(client.sin_addr.s_addr);
                if(p != -1)
                {
                    memcpy(peer_ua[p], rb+1, 63);
                    peer_ua[p][63] = 0x00;
                }
            }

            //the replay peer is setting block height
            else if(rb[0] == 'h' && read_size == sizeof(uint)+1)
            {
                //`hk; Allows master to resync from any peer, any time, injection is just as fine.
// #if MASTER_NODE == 1
//                 client.sin_addr.s_addr = replay_allow[0];
// #endif

                //Check this is the replay peer
                if(client.sin_addr.s_addr == replay_allow[0] || client.sin_addr.s_addr == replay_allow[1] || client.sin_addr.s_addr == replay_allow[2] || client.sin_addr.s_addr == replay_allow[3] || client.sin_addr.s_addr == replay_allow[4] || client.sin_addr.s_addr == replay_allow[5] || isMasterNode(client.sin_addr.s_addr) == 1)
                {
                    uint32_t trh = 0;
                    memcpy(&trh, rb+1, sizeof(uint)); //Set the block height
                    if(trh > replay_height)
                        replay_height = trh;
                    forceWrite(".vfc/rph.mem", &replay_height, sizeof(uint));
                }
            }

            //peer is requesting an address balance
            else if(rb[0] == '$' && read_size == ECC_CURVE+2)
            {
                //Check this is the replay peer
                if(isPeer(client.sin_addr.s_addr) == 1)
                {
                    //Get balance for supplied address
                    addr from;
                    memcpy(from.key, rb+1, ECC_CURVE+1);
                    const uint64_t bal = getBalanceLocal(&from);

                    //Send back balance for the supplied address
                    char pc[64];
                    pc[0] = 'n';
                    char* ofs = pc+1;
                    memcpy(ofs, &bal, sizeof(uint64_t));
                    csend(client.sin_addr.s_addr, pc, 1+sizeof(uint64_t));
                }
            }

            //peer is sending an address balance
            else if(rb[0] == 'n' && read_size == sizeof(uint64_t)+1)
            {
                //Check this is the replay peer
                const int p = getPeer(client.sin_addr.s_addr);
                if(p != -1)
                {
                    //Load the current state (check if the client process reset the log)
                    uint64_t baln=0, balt=0;
                    forceRead(".vfc/bal.mem", &baln, sizeof(uint64_t));
                    forceRead(".vfc/balt.mem", &balt, sizeof(uint64_t));

                    //Is it time to reset?
                    if(baln == 0)
                        balance_accumulator = 0;
                    if(balt == 0)
                        for(uint i = 0; i < MAX_PEERS; i++)
                            peer_ba[i] = 0;

                    //Log the new balances
                    uint64_t bal = 0;
                    memcpy(&bal, rb+1, sizeof(uint64_t));
                    peer_ba[p] = bal;
                    if(bal > balance_accumulator) //Update accumulator if higher balance returned
                        balance_accumulator = bal;

                    //And write
                    forceWrite(".vfc/bal.mem", &balance_accumulator, sizeof(uint64_t));
                    const uint64_t tb = trueBalance();
                    forceWrite(".vfc/balt.mem", &tb, sizeof(uint64_t));
                }
            }

            //peer is sending a replay block
            else if(rb[0] == 'p' && read_size == replay_size)
            {
                //`hk; Allows master to resync from any peer, any time, injection is just as fine.
// #if MASTER_NODE == 1
//                 client.sin_addr.s_addr = replay_allow[0];
// #endif

                //This replay has to be from a single peer and the master.
                if(client.sin_addr.s_addr == inet_addr("127.0.0.1") || client.sin_addr.s_addr == replay_allow[0] || client.sin_addr.s_addr == replay_allow[1] || client.sin_addr.s_addr == replay_allow[2] || client.sin_addr.s_addr == replay_allow[3] || client.sin_addr.s_addr == replay_allow[4] || client.sin_addr.s_addr == replay_allow[5] || isMasterNode(client.sin_addr.s_addr) == 1)
                {
                    //Decode packet into a Transaction
                    struct trans t;
                    memset(&t, 0, sizeof(struct trans));
                    char* ofs = rb+1;
                    memcpy(&t.uid, ofs, sizeof(uint64_t)); //grab uid
                    ofs += sizeof(uint64_t);
                    memcpy(t.from.key, ofs, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(t.to.key, ofs, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(&t.amount, ofs, sizeof(mval));
                    ofs += sizeof(mval);
                    memcpy(t.owner.key, ofs, ECC_CURVE*2);

                    //Alright process it, if it was a legitimate transaction we retain it in our chain.
                    aQue(&t, 0, 0, 0);
                }
            }

            //Anon is IPv4 scanning for peers: tell Anon we exist but send our mid code, if Anon responds with our mid code we add Anon as a peer
            else if(rb[0] == '\t' && read_size == sizeof(mid))
            {
                rb[0] = '\r';
                csend(client.sin_addr.s_addr, rb, read_size);
                addPeer(client.sin_addr.s_addr); //I didn't want to have to do this, but it's not the end of the world.
            }
            else if(rb[0] == '\r' && read_size == sizeof(mid)) //Anon responded with our mid code, we add Anon as a peer
            {
                if( rb[1] == mid[1] && //Only add as a peer if they responded with our private mid code
                    rb[2] == mid[2] &&
                    rb[3] == mid[3] &&
                    rb[4] == mid[4] &&
                    rb[5] == mid[5] &&
                    rb[6] == mid[6] &&
                    rb[7] == mid[7] )
                {
                    addPeer(client.sin_addr.s_addr);
                }
            }

            //master is requesting clients reward public key to make a payment
            else if(rb[0] == 'x' && read_size == 1)
            {
                //Only the master can pay out rewards from the pre-mine
                if(isMasterNode(client.sin_addr.s_addr) == 1)
                    csend(client.sin_addr.s_addr, myrewardkey, strlen(myrewardkey));
            }


            //Log Requests per Second
            if(st < time(0))
            {
                //Log Metrics
                printf("\x1B[33mSTAT: Req/s: %ld, Peers: %u/%u, UDP Que: %u/%u, Threads: %u/%u, Errors: %llu\x1B[0m\n", reqs / (time(0)-tt), countLivingPeers(), num_peers, gQueSize(), MAX_TRANS_QUEUE, threads, MAX_THREADS, err);

                //Prep next loop
                reqs = 0;
                tt = time(0);
                st = time(0)+180;
            }
        }
    }
    
    //Daemon
    return 0;
}
