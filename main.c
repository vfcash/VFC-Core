/*
    VF Cash is the creation of James William Fletcher
    A Cryptocurrency for Linux written in C.
    https://vfcash.uk

    The VF CASH logo was created by Futoshi Tanaka, 2019.

    CRYPTO:
    - https://github.com/brainhub/SHA3IUF   [SHA3]
    - https://github.com/esxgx/easy-ecc     [ECDSA]

    Additional Dependencies:
    - CRC64.c - Salvatore Sanfilippo
    - Base58.c - Luke Dashjr
    - SHA3.c - Andrey Jivsov

~~
    PERFORMANCE:

    One CPU core can do on average 14 transactions per second, on a 16 thread machine
    that's roughly 224 transactions a second.

    The node is capped at 2,700 transactions per second regardless of how many
    threads your machine has available. 
~~

    NOTES:
    Only Supports IPv4 addresses.
    Local storage in ~/.vfc

    *** Nodes only track peer's who send a transaction to the server from and to the same address. ***
    ~
    Peers can only be part of the network by proving they control VFC currency in a
    given VFC address. This is done by making a transaction from the same IP as the
    node running the full time VFC daemon. This transaction has to be a transaction
    to itself [a transaction from the same address it is sent to].
        Only then will the local VFC daemon receive all transactions broadcast
    around the VFC p2p network.
    ~

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
#include <sys/sysinfo.h> //cpu cores
#include <sys/stat.h> //mkdir
#include <fcntl.h> //open
#include <time.h> //time
#include <sys/mman.h> //mmap
#include <unistd.h> //sleep
#include <sys/utsname.h> //uname
#include <locale.h> //setlocale
#include <signal.h> //SIGPIPE
#include <pthread.h> //threading
#include <execinfo.h> //backtrace
#include <netdb.h> //gethostbyname

#include "ecc.h"
#include "sha3.h"
#include "crc64.h"
#include "base58.h"

#include "fixed.h"

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////

//Client Configuration
const char version[]="0.71";
const uint16_t gport = 8787;

//Error Codes
#define ERROR_NOFUNDS -1
#define ERROR_SIGFAIL -2
#define ERROR_UIDEXIST -3
#define ERROR_WRITE -4
#define ERROR_OPEN -5

//Node Settings
#define MAX_TRANS_QUEUE 8192            // Maximum transaction backlog to keep in real-time [8192 / 3 = 2,730 TPS]
#define MAX_PEERS 3072                  // Maximum trackable peers at once (this is a high enough number)
#define MAX_PEER_EXPIRE_SECONDS 10800   // Seconds before a peer can be replaced by another peer. secs(3 days=259200, 3 hours=10800)
#define PING_INTERVAL 270               // How often to ping the peers and see if they are still alive in seconds
#define REPLAY_SIZE 6944                // How many transactions to send a peer in one replay request , 2mb 13888 / 1mb 6944
#define MAX_THREADS_BUFF 512            // Maximum threads allocated for replay, dynamic scale cannot exceed this. [replay sends]
#define QUERY_TIMEOUT 3                 // Maximum seconds before an address transaction history query times out on master nodes
#define timeout_attempts 333

//Generic Buffer Sizes
#define RECV_BUFF_SIZE 256
#define MIN_LEN 256

//Chain Paths
#define CHAIN_FILE ".vfc/blocks.dat"
#define BADCHAIN_FILE ".vfc/bad_blocks.dat"
#define CONFIG_FILE ".vfc/vfc.cnf"

//Vairable Definitions
#define uint uint32_t
#define mval uint32_t
#define ulong unsigned long long int

//Operating Global Variables
char mid[8];                         //Clients private identification code used in pings etc.
float node_difficulty = 0.031;       //legacy
float network_difficulty = 0.031;    //Assumed or actual network difficulty (starts at lowest until known)
ulong err = 0;                       //Global error count
uint replay_allow[MAX_PEERS];        //IP address of peer allowed to send replay blocks
uint replay_height = 0;              //Block Height of current peer authorized to receive a replay from
char myrewardkey[MIN_LEN];           //client reward addr public key
char myrewardkeyp[MIN_LEN];          //client reward addr private key
uint8_t genesis_pub[ECC_CURVE+1];    //genesis address public key
uint thread_ip[MAX_THREADS_BUFF];    //IP's replayed to by threads (prevents launching a thread for the same IP more than once)
uint nthreads = 0;                   //number of running mining threads
uint threads = 0;                    //number of running replay threads
uint num_processors = 1;             //number of logical processors on the device
size_t MAX_SITES = 11111101;         //Maximum UID hashmap slots (11111101 = 11mb) it's a prime number, for performance, only use primes. [433024253 = 3,464 mb]
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex3 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex4 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex5 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex6 = PTHREAD_MUTEX_INITIALIZER;


//User-Configurable
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
uint single_threaded = 0;
uint replay_packet_delay = 1000;

//maximum number of replay threads
uint max_replay_threads = 6;

//Peer flood protection
uint PEER_TRANSACTION_LIMIT_PER_MINUTE = 540; // 180 = 3 unique transactions per second per peer limit

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
/* ~ Util Functions
*/

//Round a floating point
float roundFloat(const float f)
{
    if(f == 0)
        return 0;
    return roundf(f * 1000) / 1000;
}

//Convert to decimal balance
double toDB(const uint64_t b)
{
    if(b == 0)
        return 0;
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

uint qRand(const uint min, const uint umax)
{
    static float rndmax = (float)RAND_MAX;
    static time_t ls = 0;
    if(time(0) > ls)
    {
        srand(time(0));
        ls = time(0) + 33;
    }
    const float rv = (float)rand();
    const uint max = umax + 1;
    if(rv == 0)
        return min;
    return ( (rv / rndmax) * (max-min) ) + min; //(rand()%(max-min))+min;
}

float qRandFloat(const float min, const float max)
{
    static float rndmax = (float)RAND_MAX;
    static time_t ls = 0;
    if(time(0) > ls)
    {
        srand(time(0));
        ls = time(0) + 33;
    }
    const float rv = (float)rand();
    if(rv == 0)
        return min;
    return ( (rv / rndmax) * (max-min) ) + min;
}

void timestamp()
{
    const time_t ltime = time(0);
    printf("%s", asctime(localtime(&ltime)));
}

uint isalonu(char c)
{
    if((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122))
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

    uint fc = 0;
    while(f == NULL)
    {
        fc++;
        if(fc > timeout_attempts)
        {
            printf("ERROR: fopen() in forceWrite() has failed for '%s'.\n", file);
            err++;
            return;
        }

        f = fopen(file, "w");
    }

    fc = 0;
    while(fwrite(data, 1, data_len, f) < data_len)
    {
        fclose(f);
        f = fopen(file, "w");
        fc++;
        if(fc > timeout_attempts)
        {
            printf("ERROR: fwrite() in forceWrite() has failed for '%s'.\n", file);
            err++;
            return;
        }
        if(f == NULL)
            continue;
    }

    fclose(f);
}

void forceRead(const char* file, void* data, const size_t data_len)
{
    FILE* f = fopen(file, "r");

    uint fc = 0;
    while(f == NULL)
    {
        fc++;
        if(fc > timeout_attempts)
        {
            if(data_len != sizeof(uint)*MAX_PEERS) //Ignore rp.mem error
            {
                printf("ERROR: fopen() in forceRead() has failed for '%s'.\n", file);
                err++;
            }
            return;
        }

        f = fopen(file, "r");
    }

    fc = 0;
    while(fread(data, 1, data_len, f) < data_len)
    {
        fclose(f);
        f = fopen(file, "r");
        fc++;
        if(fc > timeout_attempts)
        {
            if(data_len != sizeof(uint)*MAX_PEERS) //Ignore rp.mem error
            {
                printf("ERROR: fread() in forceRead() has failed for '%s'.\n", file);
                err++;
            }
            fclose(f);
            return;
        }
        if(f == NULL)
            continue;
    }

    fclose(f);
}

void forceTruncate(const char* file, const size_t pos)
{
    int f = open(file, O_WRONLY);
    if(f)
    {
        uint c = 0;
        while(ftruncate(f, pos) == -1)
        {
            close(f);
            f = open(file, O_WRONLY);
            c++;
            if(c > timeout_attempts)
            {
                printf("ERROR: truncate() in forceTruncate() has failed for '%s'.\n", file);
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

//Only needs to support IPv4 as such using the depreciated gethostbyname() function over getaddrinfo()
uint32_t HOSTtoIPv4(const char* ihost)
{
    struct hostent* host = gethostbyname(ihost);
    if(host == NULL) 
        return 0;

    struct in_addr** addr = (struct in_addr**)host->h_addr_list;
    for(int i = 0; addr[i] != NULL; i++) 
        return addr[i]->s_addr;

    return 0;
}

uint getReplayRate()
{
    // 1,000,000 microseconds = 1 second
    // every 1,000 microseconds 1 packet is sent = 1,000 packets per second.
    return replay_packet_delay;
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

void init_sites(const size_t ims)
{
    MAX_SITES = ims;
    sites = malloc(MAX_SITES * sizeof(struct site));
    if(sites == NULL)
    {
        perror("Failed to allocate memory for the Unique Store.\n");
        exit(0);
    }

    memset(sites, 0, MAX_SITES * sizeof(struct site));
}

//Check against all uid in memory for a match
uint has_uid(const uint64_t uid) //Pub
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

    //Always update expirary
    sites[site_index].expire_epoch = time(0)+expire_seconds;

    //Reset if expire_epoch dictates this site bucket is expired 
    if(time(0) >= sites[site_index].expire_epoch)
    {
        sites[site_index].uid_low = 0;
        sites[site_index].uid_high = 0;
    }

    //Find the range
    unsigned short idfar = (uid % (sizeof(unsigned short)-1))+1;

    //Collison?
    if(sites[site_index].uid_low != 0 && (sites[site_index].uid_low != idfar && sites[site_index].uid_high != idfar))
        printf("UID Collision: %u\n", site_index);

    //Set the ranges
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

    if((m1 == 0 || m2 == 0) || dot == 0)
        return 1; //returns angle that is too wide, exclusion / (aka/equiv) ret0

    return dot / (m1*m2); //Should never divide by 0
}

inline static double getMiningDifficulty()
{ 
    return network_difficulty;
}

inline static uint64_t avg_diff2val(const double ra)
{
    return (uint64_t)floor(( 1000 + ( 10000*(1-(ra*4.166666667)) ) )+0.5);
}

//This is the algorthm to check if a genesis address is a valid "SubGenesis" address
uint64_t isSubGenesisAddressMine(uint8_t *a)
{
    //Requesting the balance of a possible existing subG address

    vec3 v[5]; //Vectors

    uint8_t *ofs = a;
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
    const double min = MIN_DIFFICULTY;
    
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
        printf("subG: %.8f - %.8f - %.8f - %.8f - %'.3f VFC < %.3f\n\n", a1, a2, a3, a4, toDB(rv), ra);

        return rv;
    }

    //Print the occasional "close hit"
    const double soft = 0.1;
    if(a1 < min+soft && a2 < min+soft && a3 < min+soft && a4 < min+soft)
        printf("x: %.8f - %.8f - %.8f - %.8f\n", a1, a2, a3, a4);

    return 0;

}

double isSubDiff(uint8_t *a)
{
    vec3 v[5]; //Vectors

    uint8_t *ofs = a;
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

    //printf("%.3f - %.3f - %.3f - %.3f\n", a1,a2,a3,a4);
    double diff = a1;
    if(a2 > diff)
        diff = a2;
    if(a3 > diff)
        diff = a3;
    if(a4 > diff)
        diff = a4;
    return diff;
}

//This is the algorthm to check if a genesis address is a valid "SubGenesis" address
uint64_t isSubGenesisAddress(uint8_t *a, const uint fr)
{
    //Is this requesting the genesis balance
    if(memcmp(a, genesis_pub, ECC_CURVE+1) == 0)
    {
        //Get the tax
        struct stat st;
        const int sr = stat(CHAIN_FILE, &st);
        uint64_t ift = 0;
        if(sr == 0 && st.st_size > 0)
            ift = (uint64_t)st.st_size / sizeof(struct trans);
        else
            return 0;
        
        ift *= INFLATION_TAX; //every transaction inflates vfc by 1 VFC (1000v). This is a TAX paid to miners.
        return ift;
    }

    //Requesting the balance of a possible existing subG address

    vec3 v[5]; //Vectors

    uint8_t *ofs = a;
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
    const double min = fr == 0 ? getMiningDifficulty() : 0.24;

    //printf("%.3f - %.3f - %.3f - %.3f > %.3f\n", a1,a2,a3,a4,min);
    
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
// ~ P2P Tracker

//General peer tracking
uint peers[MAX_PEERS]; //Peer IPv4 addresses
time_t peer_timeouts[MAX_PEERS]; //Peer timeout UNIX epoch stamps
uint num_peers = 0; //Current number of indexed peers
uint peer_tcount[MAX_PEERS]; //Amount of transactions relayed by peer
uint peer_ltcount[MAX_PEERS]; //delta tcount for flood protection / rate limiting
char peer_ua[MAX_PEERS][64]; //Peer user agent
time_t peer_rm[MAX_PEERS]; //Last time peer responded to a mid request

uint countPeers() //generates num_peers on load
{
    uint c = 1; //skip the master, as some times master could end up as 0
    for(uint i = 1; i < MAX_PEERS; i++)
    {
        if(peers[i] == 0) //in which case this will then prevent peers from listing
            return c;
        c++;
    }
    return c;
}

uint isPeerAlive(const uint id)
{
    if(id == 0) //SEED-NODE always considered alive.
        return 1;
    if(peers[id] == 0)
        return 0;
    const uint pd = time(0)-(peer_timeouts[id]-MAX_PEER_EXPIRE_SECONDS);
    const uint md = time(0) - peer_rm[id];  // WARNING:   if there is ever network connectivity issues peers that can't send across a MID in time can never re-index without a "flushpeers"
                                            // CORRECTED: peersBroadcastAll() will now send mid request to all peers including dead.
    if(pd <= PING_INTERVAL*20 && md <= PING_INTERVAL*64)
        return 1;
    return 0;
}

uint countLivingPeers()
{
    uint c = 1; //Assume master to always be alive
    for(uint i = 1; i < num_peers; i++)
    {
        if(isPeerAlive(i) == 1)
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
    printf("\nScanning the entire IPv4 range of ~4.3 billion checking for peers.\n\n");

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

    //Check for genesis transaction
    FILE* f = fopen(path, "r");
    if(f)
    {
        //Is the correct genesis block?
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
        printf("Look's like the blocks.dat cannot be found please make sure you chmod 700 ~/.vfc\n");
        return 0;
    }
    
    //Verified
    return 1;
}

uint isSeedNode(const uint ip)
{
    if(ip == peers[0])
        return 1;
    return 0;
}

void setSeedNode()
{
    peers[0] = HOSTtoIPv4("vfcash.co.uk");
    sprintf(peer_ua[0], "VFC-SEED");
}

void peersBroadcast(const char* dat, const size_t len)
{
    for(uint i = 0; i < num_peers; ++i)
        if(isPeerAlive(i) == 1)
            csend(peers[i], dat, len);
}

void peersBroadcastAll(const char* dat, const size_t len)
{
    for(uint i = 0; i < num_peers; ++i)
        csend(peers[i], dat, len);
}

void broadcastUserAgent()
{
    struct stat st;
    const int sr = stat(CHAIN_FILE, &st);
    struct utsname ud;
    uname(&ud);
    char pc[MIN_LEN];
    if(sr == 0 && st.st_size > 0)
    {
        snprintf(pc, sizeof(pc), "a%lu, %s, %u, %s, %.3f", st.st_size / sizeof(struct trans), version, num_processors, ud.machine, node_difficulty);
        peersBroadcast(pc, strlen(pc));
    }
}

void triBroadcast(const char* dat, const size_t len, const uint multi)
{
    if(num_peers > multi)
    {
        for(uint t = 0; t < multi; t++)
        {
            uint si = qRand(0, num_peers-1);
            uint fc = 0;
            while(1)
            {
                if(isPeerAlive(si) == 1)
                    break;
                    
                si++;
                if(si >= num_peers)
                {
                    si = 0;

                    fc++;
                    if(fc > 1)
                    {
                        //printf("ERROR: triBroadcast() has failed to find a living peer.\n");
                        //err++;
                        return;
                    }
                }
            }

            csend(peers[si], dat, len);
        }
    }
    else
    {
        for(uint p = 0; p < num_peers; p++) //WARNING: packets could leak to possible rogue dead peers, not critical but worth considering.
            csend(peers[p], dat, len);
    }
}

void resyncBlocks(const uint irnp)
{
    //Clear replay_allow
    memset(&replay_allow, 0, sizeof(uint)*MAX_PEERS);

    //allow replay from x peers at random offset
    const uint rnp = irnp < num_peers ? irnp : num_peers-1; //Replay Num Peers
    int i = 0;
    int ri = 0;
    if(num_peers-rnp != 0) //We have offset leeway
        i = qRand(0, num_peers-rnp); //Select a random offset between 0 and leeway
    //printf("Replay from %i peers, offset %i out of %u peers.\n\n", rnp, i, num_peers);
    for(; i < rnp; i++, ri++) //Iterate RNP from i offset
    {
        replay_allow[ri] = peers[i];
        csend(peers[i], "r", 1);
    }
    
    //Set the file memory
    forceWrite(".vfc/rp.mem", &replay_allow, sizeof(uint)*MAX_PEERS);
}

uint isPeer(const uint ip)
{
    if(ip == inet_addr("127.0.0.1"))
        return 1;

    for(uint i = 0; i < num_peers; ++i)
    {
        if(peers[i] == ip)
        {
            peer_timeouts[i] = time(0) + MAX_PEER_EXPIRE_SECONDS;
            return 1;
        }
    }
    return 0;
}

int getPeer(const uint ip)
{
    for(uint i = 0; i < num_peers; ++i)
        if(peers[i] == ip)
            return i;
    return -1;
}

size_t getPeerHigh(const uint id)
{
    const char* str = strtok(peer_ua[id], ",");
    if(str != NULL)
        return strtoul(str, NULL, 10);
    else
        return 0;
}

float getPeerDiff(const uint id)
{
    char cf[8];
    memset(cf, 0, sizeof(char)*8);
    const uint ual = strlen(peer_ua[id]);

    if(ual > 6)
    {
        if(peer_ua[id][ual-5] == '0' && peer_ua[id][ual-4] == '.')
        {
            cf[0] = peer_ua[id][ual-5];
            cf[1] = peer_ua[id][ual-4];
            cf[2] = peer_ua[id][ual-3];
            cf[3] = peer_ua[id][ual-2];
            cf[4] = peer_ua[id][ual-1];
        }
        else
        {
            return 0.031;
        }
    }
    else
    {
        return 0.031;
    }
    
    float rv = atof(cf);
    if(rv < 0.031)
        rv = 0.031;
    if(rv > MIN_DIFFICULTY)
        rv = MIN_DIFFICULTY;
    return roundFloat(rv);
}

void printDifficultySpread() //Legacy, remove in future
{
    uint tally[256];
    memset(tally, 0, sizeof(uint)*256);
    for(uint p = 0; p < MAX_PEERS; p++)
    {
        if(isPeerAlive(p) == 1)
        {
            //Peer difficulty index
            const double diff = getPeerDiff(p);

            //Is it in the valid range
            if(diff >= 0.030 && diff <= 0.241)
            {
                const int ti = diff * 1000;
                tally[ti]++;
            }
        }
    }
    for(uint i = 31; i < 241; i++)
        printf("%.3f,%u\n", (double)i/1000, tally[i]);
}

//Peers are only replaced if they have not responded in a x time period.
int addPeer(const uint ip)
{
    //Is there room for a new peer?
    if(num_peers >= MAX_PEERS)
        return 0;

    //Never add local host
    if(ip == inet_addr("127.0.0.1")) //inet_addr("127.0.0.1") //0x0100007F
        return -1;

    //Or local network address
    if(isPrivateAddress(ip) == 1)
        return -1;

    //Is already in peers?
    uint freeindex = 0;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_lock(&mutex4);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    for(uint i = 0; i < num_peers; ++i)
    {
        if(peers[i] == ip)
        {

            peer_timeouts[i] = time(0) + MAX_PEER_EXPIRE_SECONDS;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex4);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            return i; //exists
        }

        if(freeindex == 0 && i != 0 && (peer_timeouts[i] < time(0) && time(0) > peer_rm[i]+PING_INTERVAL)) //0 = Master, never a free slot.
            freeindex = i;
    }

    //Try to add to a free slot first
    if(num_peers < MAX_PEERS)
    {
        peers[num_peers] = ip;
        peer_timeouts[num_peers] = time(0) + MAX_PEER_EXPIRE_SECONDS;
        peer_tcount[num_peers] = 1;
        peer_rm[num_peers] = time(0);
        num_peers++;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex4);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        return num_peers;
    }
    else if(freeindex != 0) //If not replace a node that's been quiet for more than three hours
    {
        peers[freeindex] = ip;
        peer_timeouts[freeindex] = time(0) + MAX_PEER_EXPIRE_SECONDS;
        peer_tcount[freeindex] = 1;
        peer_rm[freeindex] = time(0);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex4);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        return freeindex;
    }
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex4);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
    {
        //printf("AMOUNT-ZERO: %lu\n", t->uid);
        return 0; //Don't tell the other peers, pointless transaction
    }

    //Do a quick unique check [realtime uid cache]
    if(memcmp(t->from.key, t->to.key, ECC_CURVE+1) == 0) //is auth trans
    {
        if(has_uid(crc64(0, (unsigned char*)t->from.key, ECC_CURVE+1)) == 1)
            return 0;
    }
    else
    {
        //The only kind of transaction a non-peer can send is a network auth (replays specify both ip's as 0/null so there is exception for this)
        if( (iipo != 0 && isPeer(iip) == 0) || (iipo != 0 && isPeer(iipo) == 0) )
        {
            //printf("NOT-PEER: %lu\n", t->uid);
            return 0;
        }

        //Check it's not on the cache block
        if(has_uid(t->uid) == 1)
        {
            //printf("HAS-UID: %lu\n", t->uid);
            return 0;
        }
    }

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_lock(&mutex5);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    //Check if duplicate transaction
    int freeindex = -1;
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].amount != 0)
        {
            //Is this a possible double spend?
            if(ir == 1 && replay[i] == 1)
            {
                if((memcmp(tq[i].from.key, t->from.key, ECC_CURVE+1) == 0 && memcmp(tq[i].to.key, t->to.key, ECC_CURVE+1) != 0))
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
                    add_uid(t->uid, 30); //block uid 30 seconds
                    add_uid(tq[i].uid, 30); //block original uid 30 seconds
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex5);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    return 2; //Don't process this transaction and do tell our peers about this transaction so that they have detect and terminate also.
                }
            }

            //UID already in queue?
            if(tq[i].uid == t->uid)
            {
                //printf("ALREADY-IN-QUE: %lu\n", t->uid);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex5);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                return 0; //It's not a double spend, just a repeat, don't tell our peers
            }
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
    if(memcmp(t->from.key, t->to.key, ECC_CURVE+1) == 0) //is auth trans
    {
        add_uid(crc64(0, (unsigned char*)t->from.key, ECC_CURVE+1), 1600); //26 min for auth trans
    }
    else
    {
        add_uid(t->uid, 30); //block uid for 9 hours (there can be collisions, as such it's a temporary block)
    }

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex5);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    return 1;
}

//pop the first living transaction index off the Queue
int gQue()
{
    const uint mi = qRand(3, MAX_TRANS_QUEUE-3);
    for(int i = mi; i >= 0; i--) //Check left first, que is stacked left to right
    {
        if(tq[i].amount != 0)
            if(time(0) - delta[i] >= 3 || replay[i] == 0) //Only process transactions at least 3 second old [replays are instant]
                return i;
    }
    for(int i = mi; i < MAX_TRANS_QUEUE; i++) //now check to the right of random index
    {
        if(tq[i].amount != 0)
            if(time(0) - delta[i] >= 3 || replay[i] == 0) //Only process transactions at least 3 second old [replays are instant]
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

                if(memcmp(t.from.key, genesis_pub, ECC_CURVE+1) != 0)
                {
                    const uint64_t w = isSubGenesisAddress(t.from.key, 1);
                    if(w > 0)
                    {
                        rv += w;
                    }
                }
            }

            munmap(m, len);
        }

        close(f);
    }
    return rv;
}

//Get circulating supply
uint64_t getCirculatingSupply()
{
    //Get the tax
    struct stat st;
    const int sr = stat(CHAIN_FILE, &st);
    uint64_t ift = 0;
    if(sr == 0 && st.st_size > 0)
        ift = (uint64_t)st.st_size / sizeof(struct trans);
    ift *= INFLATION_TAX; //every transaction inflates vfc by 1 VFC (1000v). This is a TAX paid to miners.

    //Difficulty burning addresses
    struct addr lpub;
    size_t len = ECC_CURVE+1;
    b58tobin(lpub.key, &len, "q15voteVFCf7Csb8dKwaYkcYVEWa2CxJVHm96SGEpvzK", 44);
    struct addr tpub;
    len = ECC_CURVE+1;
    b58tobin(tpub.key, &len, "24KvoteVFC7JsTiFaGna9F6RhtMWdB7MUa3wZoVNm7wH3", 45);

    //IFT
    uint64_t rv = 0;
    if(ift > 0)
        rv = (ift / 100) * 20; // 20% of the ift tax
    
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

                //Negate payments to difficulty burn addresses
                if(memcmp(t.to.key, lpub.key, ECC_CURVE+1) == 0 || memcmp(t.to.key, tpub.key, ECC_CURVE+1) == 0)
                    rv -= t.amount;

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

            munmap(m, len);
        }

        close(f);
    }
    return rv;
}



//Replay thread queue
uint32_t replay_peers[MAX_THREADS_BUFF];

//Get replay peer
uint32_t getRP()
{
pthread_mutex_lock(&mutex6);
    for(int i = 0; i < max_replay_threads; ++i)
    {
        if(replay_peers[i] != 0)
        {
            const uint32_t r = replay_peers[i];
            replay_peers[i] = 0;
            pthread_mutex_unlock(&mutex6);
            return r;
        }
    }
pthread_mutex_unlock(&mutex6);
    return 0;
}

//Set replay peer ip
void setRP(const uint32_t ip)
{
pthread_mutex_lock(&mutex6);
    for(int i = 0; i < max_replay_threads; ++i)
    {
        if(replay_peers[i] == 0)
        {
            replay_peers[i] = ip;
            break;
        } 
    }
pthread_mutex_unlock(&mutex6);
}

//Replay blocks to x address
void replayHead(const uint ip, const size_t rlen)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;

    const uint replay_rate = getReplayRate();

    //Send block height
    struct stat st;
    const int sr = stat(CHAIN_FILE, &st);
    if(sr == 0 && st.st_size > 0)
    {
        char pc[MIN_LEN];
        pc[0] = 'h';
        char* ofs = pc + 1;
        const uint height = st.st_size;
        memcpy(ofs, &height, sizeof(uint));
        csend(ip, pc, 1+sizeof(uint));
        printf("Replaying Head: %.1f kb to %s\n", (double) ( sizeof(struct trans) * rlen ) / 1000, inet_ntoa(ip_addr));
    }

    //Replay blocks
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);
        
        size_t end = len-(rlen*sizeof(struct trans)); //top len transactions
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
                if(fc > timeout_attempts)
                {
                    printf("ERROR: fread() in replayHead() #1 has failed for peer %s\n", inet_ntoa(ip_addr));
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

            //Log
            //printf("%s: %lu\n", inet_ntoa(ip_addr), t.uid);

            //Rate limit
            usleep(replay_rate);
        }

        fclose(f);
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
    const int sr = stat(CHAIN_FILE, &st);
    if(sr == 0 && st.st_size > 0)
    {
        char pc[MIN_LEN];
        pc[0] = 'h';
        char* ofs = pc + 1;
        const uint height = st.st_size;
        memcpy(ofs, &height, sizeof(uint));
        csend(ip, pc, 1+sizeof(uint));
        printf("Replaying Blocks: %.1f kb to %s\n", (double) ( sizeof(struct trans) * REPLAY_SIZE ) / 1000, inet_ntoa(ip_addr));
    }

    //Replay blocks
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const size_t len = ftell(f);
        if(len == 0)
        {
            fclose(f);
            return;
        }

        //Pick a random block of data from the chain of the specified REPLAY_SIZE
        const size_t rpbs = (sizeof(struct trans)*REPLAY_SIZE);
        const size_t lp = len / rpbs; //How many REPLAY_SIZE fit into the current blockchain length
        const size_t st = sizeof(struct trans) + (rpbs * qRand(1, lp-1)); //Start at one of these x offsets excluding the end of the last block (no more blocks after this point)
        size_t end = st+rpbs; //End after that offset + REPLAY_SIZE amount of transactions later

        struct trans t;
        for(size_t i = st; i < len && i < end; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);

            uint fc = 0;
            while(fread(&t, 1, sizeof(struct trans), f) != sizeof(struct trans))
            {
                fclose(f);
                f = fopen(CHAIN_FILE, "r");
                fc++;
                if(fc > timeout_attempts)
                {
                    printf("ERROR: fread() in replayBlocks() #2 has failed for peer %s\n", inet_ntoa(ip_addr));
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

            // rate limit
            usleep(replay_rate);
        }

        fclose(f);
    }
}
void *replayBlocksThread(void *arg)
{
    //Prep the thread
    if(chdir(getHome()) == -1)
    {
pthread_mutex_lock(&mutex1);
        threads--;
pthread_mutex_unlock(&mutex1);
        return 0;
    }
    if(nice(19) == -1) //Very low priority thread
        printf("ERROR: replayBlocksThread() nice(19) failed.\n");

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

    //Get peer by ip
    const uint peer = getPeer(ip);
    if(peer != -1)
    {
        //Get peer height
        const size_t peer_high = getPeerHigh(peer);
        
        //Get my height
        struct stat st;
        stat(CHAIN_FILE, &st);
        const size_t my_high = st.st_size > 0 ? st.st_size / sizeof(struct trans) : 0;

        //if peer has a smaller block height
        const int diff = my_high - peer_high;
        if(diff != 0)
        {
            if(diff <= REPLAY_SIZE && diff > 0) //Give peer the fast update
            {
                //Give the peer double the head they need, just to be sure !
                replayHead(ip, diff*2);
            }
            else
            {
                if(peer_high < my_high)
                {
                    //Give peer a random block because the peer is way behind
                    replayBlocks(ip);
                }
                else
                {
                    //Just give the peer *some* head, because the peer is way ahead of us and only our latest graph ends are potentially useful
                    replayHead(ip, REPLAY_SIZE*3);
                }
            }
        }
    }

    //End the thread
pthread_mutex_lock(&mutex1);
    threads--;
    for(int i = 0; i < max_replay_threads; i++)
        if(thread_ip[i] == ip)
            thread_ip[i] = 0;
pthread_mutex_unlock(&mutex1);
    return 0;
}

//Launch a replay thread
void launchReplayThread(const uint32_t ip)
{
    //Are there enough thread slots left?
    if(threads >= max_replay_threads)
        return;

    //Are we already replaying to this IP address?
    uint cp = 1;
    for(uint i = 0; i < max_replay_threads; i++)
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

//dump all trans
void dumptrans(const size_t offset)
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

                char topub[MIN_LEN];
                memset(topub, 0, sizeof(topub));
                size_t len = MIN_LEN;
                b58enc(topub, &len, t.to.key, ECC_CURVE+1);

                char frompub[MIN_LEN];
                memset(frompub, 0, sizeof(frompub));
                len = MIN_LEN;
                b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

                setlocale(LC_NUMERIC, "");
                printf("%lu: %s\n\t%s > %'.3f\n", t.uid, frompub, topub, toDB(t.amount));
            }

            munmap(m, len);
        }

        close(f);
    }
}

//dump all bad trans
void dumpbadtrans()
{
    int f = open(BADCHAIN_FILE, O_RDONLY);
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

                char topub[MIN_LEN];
                memset(topub, 0, sizeof(topub));
                size_t len = MIN_LEN;
                b58enc(topub, &len, t.to.key, ECC_CURVE+1);

                char frompub[MIN_LEN];
                memset(frompub, 0, sizeof(frompub));
                len = MIN_LEN;
                b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

                setlocale(LC_NUMERIC, "");
                printf("%lu: %s > %s : %'.3f\n", t.uid, frompub, topub, toDB(t.amount));
            }

            munmap(m, len);
        }

        close(f);
    }
}

//print top x sent & recv transactions
void printTop(addr* a, const uint num)
{
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

#if MASTER_NODE == 1
            const time_t st = time(0);
#endif
            uint tc = 0;
            struct trans t;
            for(size_t i = len-sizeof(struct trans); i > 0; i -= sizeof(struct trans))
            {
#if MASTER_NODE == 1
                if(time(0) - st > QUERY_TIMEOUT)
                {
                    printf("Query Timeout.\n");
                    break; //break the loop if the lookup is taking more than x seconds on a master node.
                }
#endif
                memcpy(&t, m+i, sizeof(struct trans));

                if(memcmp(&t.from.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.to.key, ECC_CURVE+1);
                    setlocale(LC_NUMERIC, "");
                    printf("OUT,%lu,%s,%'.3f\n", t.uid, pub, toDB(t.amount));
                    tc++;
                    if(tc >= num)
                        return;
                }
                else if(memcmp(&t.to.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.from.key, ECC_CURVE+1);
                    setlocale(LC_NUMERIC, "");
                    printf("IN,%lu,%s,%'.3f\n", t.uid, pub, toDB(t.amount));
                    tc++;
                    if(tc >= num)
                        return;
                }
            }

            munmap(m, len);
        }

        close(f);
    }
}

//print sent & recv transactions
void printAll(addr* a)
{
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

#if MASTER_NODE == 1
            const time_t st = time(0);
#endif

            struct trans t;
            for(size_t i = 0; i < len; i += sizeof(struct trans))
            {
#if MASTER_NODE == 1
                if(time(0) - st > QUERY_TIMEOUT)
                {
                    printf("Query Timeout.\n");
                    break; //break the loop if the lookup is taking more than x seconds on a master node.
                }
#endif
                memcpy(&t, m+i, sizeof(struct trans));

                if(memcmp(&t.from.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.to.key, ECC_CURVE+1);
                    setlocale(LC_NUMERIC, "");
                    printf("OUT,%lu,%s,%'.3f\n", t.uid, pub, toDB(t.amount));
                }
                else if(memcmp(&t.to.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.from.key, ECC_CURVE+1);
                    setlocale(LC_NUMERIC, "");
                    printf("IN,%lu,%s,%'.3f\n", t.uid, pub, toDB(t.amount));
                }
            }

            munmap(m, len);
        }

        close(f);
    }
}

//print received transactions
void printIns(addr* a)
{
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

#if MASTER_NODE == 1
            const time_t st = time(0);
#endif

            struct trans t;
            for(size_t i = 0; i < len; i += sizeof(struct trans))
            {
#if MASTER_NODE == 1
                if(time(0) - st > QUERY_TIMEOUT)
                {
                    printf("Query Timeout.\n");
                    break; //break the loop if the lookup is taking more than x seconds on a master node.
                }
#endif
                memcpy(&t, m+i, sizeof(struct trans));

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

            munmap(m, len);
        }

        close(f);
    }
}

//print sent transactions
void printOuts(addr* a)
{
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

#if MASTER_NODE == 1
            const time_t st = time(0);
#endif

            struct trans t;
            for(size_t i = 0; i < len; i += sizeof(struct trans))
            {
#if MASTER_NODE == 1
                if(time(0) - st > QUERY_TIMEOUT)
                {
                    printf("Query Timeout.\n");
                    break; //break the loop if the lookup is taking more than x seconds on a master node.
                }
#endif

                memcpy(&t, m+i, sizeof(struct trans));

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

            munmap(m, len);
        }

        close(f);
    }
}

void printtrans(uint fromR, uint toR)
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
            for(size_t i = fromR * sizeof(struct trans); i < len; i += sizeof(struct trans))
            {
                memcpy(&t, m+i, sizeof(struct trans));

                char from[MIN_LEN];
                memset(from, 0, sizeof(from));
                size_t len = MIN_LEN;
                b58enc(from, &len, t.from.key, ECC_CURVE+1);

                char to[MIN_LEN];
                memset(to, 0, sizeof(from));
                size_t len2 = MIN_LEN;
                b58enc(to, &len2, t.to.key, ECC_CURVE+1);

                char sig[MIN_LEN];
                memset(sig, 0, sizeof(sig));
                size_t len3 = MIN_LEN;
                b58enc(sig, &len3, t.owner.key, ECC_CURVE*2);

                setlocale(LC_NUMERIC, "");
                printf("%d,%lu,%s,%s,%s,%.3f\n", (int)(i/sizeof(struct trans)), t.uid, from, to, sig, toDB(t.amount));

                if(i >= toR * sizeof(struct trans))
                {
                    break;
                }
            }

            munmap(m, len);
        }

        close(f);
    }
}

//find a specific transaction by UID
void findTrans(const uint64_t uid)
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

                if(t.uid == uid)
                {
                    char from[MIN_LEN];
                    memset(from, 0, sizeof(from));
                    size_t len = MIN_LEN;
                    b58enc(from, &len, t.from.key, ECC_CURVE+1);

                    char to[MIN_LEN];
                    memset(to, 0, sizeof(from));
                    size_t len2 = MIN_LEN;
                    b58enc(to, &len2, t.to.key, ECC_CURVE+1);

                    char sig[MIN_LEN];
                    memset(sig, 0, sizeof(sig));
                    size_t len3 = MIN_LEN;
                    b58enc(sig, &len3, t.owner.key, ECC_CURVE*2);

                    setlocale(LC_NUMERIC, "");
                    //printf("%lu: %s > %'.3f\n", t.uid, pub, toDB(t.amount));
                    printf("%d,%lu,%s,%s,%s,%.3f\n",(int)(i/sizeof(struct trans)), t.uid, from, to, sig, toDB(t.amount));

                    return;
                }
            }

            munmap(m, len);
        }

        close(f);
    }
    printf("Transaction could not be found.\n");
}

//broadcast x top balance to all peers at the defined delay rate
void broadcastBalance(addr* from, const uint topx, const uint delay)
{
    uint bc = 0;
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

            struct trans t;
            for(size_t i = len-sizeof(struct trans); i > 0; i -= sizeof(struct trans))
            {
                memcpy(&t, m+i, sizeof(struct trans));

                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0 || memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                {
                    const uint32_t origin = 0;
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
                    peersBroadcast(pc, len);
                    
                    bc++;
                    if(bc > topx)
                        return;

                    if(delay != 0)
                        sleep(delay); //prevent double-spend throttling
                }
            }

            munmap(m, len);
        }

        close(f);
    }
}

//get balance
uint64_t getBalanceLocal(addr* from)
{
    //Get local Balance
    int64_t rv = isSubGenesisAddress(from->key, 0);

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

                const uint64_t lrv = rv;

                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                {
                    rv += t.amount;
                }
                else if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                {
                    rv -= t.amount;
                }

#if MASTER_NODE == 0
                if(lrv != rv)
                {
                    //re-enforce each transaction over the network
                    const uint32_t origin = 0;
                    const size_t len = 1+sizeof(uint64_t)+sizeof(uint32_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
                    char pc[MIN_LEN];
                    pc[0] = 't'; //send as a regular transaction, bypass replay allow blocking but will have double spend throttling
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
                    triBroadcast(pc, len, 3); //Just tell a random few peers or we will start triggering transaction duplication logs in badblocks 
                    //                        particularly on outgoing transactions. This is just to support the replay redundency at a minimal cost.
                }
#endif
            }

            munmap(m, len);
        }

        close(f);
    }

    if(rv < 0)
        return 0;
    return rv;
}

float liveNetworkDifficulty()
{
    //Vote Less than MIN_DIFFICULTY                                                  [lb]
    struct addr lpub;
    size_t len = ECC_CURVE+1;
    b58tobin(lpub.key, &len, "q15voteVFCf7Csb8dKwaYkcYVEWa2CxJVHm96SGEpvzK", 44);

    //Vote MIN_DIFFICULTY                                                            [tb]
    struct addr tpub;
    len = ECC_CURVE+1;
    b58tobin(tpub.key, &len, "24KvoteVFC7JsTiFaGna9F6RhtMWdB7MUa3wZoVNm7wH3", 45);

    //Get addr balances
    const double lb = toDB(getBalanceLocal(&lpub)); // < MIN_DIFFICULTY vote power in vfc
    const double tb = toDB(getBalanceLocal(&tpub)); //   MIN_DIFFICULTY vote power in vfc

    //Is higher for MIN_DIFFICULTY
    float ndiff = 0.031;
    if(tb > lb)
    {
        ndiff = MIN_DIFFICULTY;
    }
    else //otherwise drag down on MIN_DIFFICULTY by the overflow balance of lb
    {
        if(lb != 0)
            ndiff = ((1 / lb) * tb) * MIN_DIFFICULTY;
    }

    //Limit
    if(ndiff < 0.031)
        ndiff = 0.031;
    if(ndiff > MIN_DIFFICULTY)
        ndiff = MIN_DIFFICULTY;

    //Round
    return roundFloat(ndiff);
}

void networkDifficulty()
{
    //Get the current network difficulty
    network_difficulty = liveNetworkDifficulty();

    //Broadcast set as node difficulty and broadcast
    node_difficulty = network_difficulty;
    broadcastUserAgent();
}

//Calculate if an address has the value required to make a transaction of x amount.
int hasbalance(const uint64_t uid, addr* from, mval amount)
{
    //Is subGenesis?
    int64_t rv = isSubGenesisAddress(from->key, 0);

    //Try to open the chain file
    int f = open(CHAIN_FILE, O_RDONLY);

    //Too critical to fail
    uint fc = 0;
    while(f == -1)
    {
        fc++;
        if(fc > timeout_attempts)
        {
            printf("ERROR: open() in hasbalance() has failed.\n");
            err++;
            return ERROR_OPEN;
        }

        f = open(CHAIN_FILE, O_RDONLY);
    }

    //Look's like we have the file handle...
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

    if(rv >= amount)
        return 1;
    else
        return 0;
}

//Execute Transaction
int process_trans(const uint64_t uid, addr* from, addr* to, mval amount, sig* owner)
{
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
        //printf("ERROR: verify failed.\n");
        return ERROR_SIGFAIL;
    }

    //Add the sig now we know it's valid
    memcpy(t.owner.key, owner->key, ECC_CURVE*2);

    //Check this address has the required value for the transaction (and that UID is actually unique)
    const int hbr = hasbalance(uid, from, amount);
    if(hbr == 0)
    {
        //printf("ERROR: no balance.\n");
        return ERROR_NOFUNDS;
    }
    else if(hbr < 0)
    {
        //printf("ERROR: uid exists.\n");
        return hbr; //it's an error code
    }

    //This check after the balance check as we need to verify transactions to self have the balance before confirming 'valid transaction'
    //you still need balance to make a transaction to self
    if(memcmp(from->key, to->key, ECC_CURVE+1) != 0) //Only log if the user was not sending VFC to themselves.
    {
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_lock(&mutex3);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        FILE* f = fopen(CHAIN_FILE, "a");

        uint fc = 0;
        while(f == NULL)
        {
            fc++;
            if(fc > timeout_attempts)
            {
                printf("ERROR: fopen() in process_trans() has failed.\n");
                err++;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex3);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                return ERROR_OPEN;
            }

            f = fopen(CHAIN_FILE, "a");
        }

        size_t written = 0;

        if(f)
        {
            fc = 0;
            while(written == 0)
            {
                written = fwrite(&t, 1, sizeof(struct trans), f);

                fc++;
                if(fc > timeout_attempts)
                {
                    printf("ERROR: fwrite() in process_trans() has failed.\n");
                    err++;
                    fclose(f);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex3);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

                    printf("ERROR: fwrite() in process_trans() reverted potential chain corruption.\n");

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

// FILE* f = fopen("/var/www/html/p_good.txt", "a");
// if(f)
// {
//     fprintf(f, "%lu : %lu / %.3f\n", time(0), t.uid, network_difficulty);
//     fclose(f);
// }

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex3);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    }
    
    //Success
    return 1;
}

void makAddrSeed(addr* pub, addr* priv, const uint64_t* seed) //Seeded [array of four uint64_t's]
{
    if(ecc_make_key_seed(pub->key, priv->key, seed) == 1)
    {
        //Dump Base58
        char bpub[MIN_LEN], bpriv[MIN_LEN];
        memset(bpub, 0, sizeof(bpub));
        memset(bpriv, 0, sizeof(bpriv));
        size_t len = MIN_LEN;
        b58enc(bpub, &len, pub->key, ECC_CURVE+1);
        b58enc(bpriv, &len, priv->key, ECC_CURVE);
        printf("\nMade new Address / Key Pair\n\nPublic: %s\n\nPrivate: %s\n\n", bpub, bpriv);
    }
    else
    {
        printf("Seed failed to create a valid private key.\n");
    }
}

void makAddr(addr* pub, addr* priv, const uint silent)
{
    //Make key pair
    ecc_make_key(pub->key, priv->key);

    //Make sure it's not a subG
    while(isSubGenesisAddress(pub->key, 1) == 1)
        ecc_make_key(pub->key, priv->key);

    //Dump Base58
    char bpub[MIN_LEN], bpriv[MIN_LEN];
    memset(bpub, 0, sizeof(bpub));
    memset(bpriv, 0, sizeof(bpriv));
    size_t len = MIN_LEN;
    b58enc(bpub, &len, pub->key, ECC_CURVE+1);
    b58enc(bpriv, &len, priv->key, ECC_CURVE);
    if(silent == 0)
        printf("\nMade new Address / Key Pair\n\nPublic: %s\n\nPrivate: %s\n\n", bpub, bpriv);
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

void loadConfig(const uint stat)
{
    if(stat == 1)
        printf("Configuration File: %s/.vfc/vfc.cnf\n", getHome());

    FILE* f = fopen(CONFIG_FILE, "r");
    if(f)
    {
        char line[256];
        while(fgets(line, 256, f) != NULL)
        {
            char set[64];
            memset(set, 0, 64);
            uint val;
            
            if(sscanf(line, "%63s %u", set, &val) == 2)
            {
                if(stat == 1)
                    printf("Setting Loaded: %s %u\n", set, val);

                if(strcmp(set, "multi-threaded") == 0)
                    single_threaded = val == 0 ? 1 : 0;

                if(strcmp(set, "replay-delay") == 0) //Default 1,000, the higher the number the less bandwith used refer to notes in getReplatRate() function.
                    replay_packet_delay = val;

                if(strcmp(set, "replay-threads") == 0) //Default is variable based on CPU core count, max is 512
                    max_replay_threads = val;

                if(strcmp(set, "peer-trans-limit-per-min") == 0) //Default is 180 - 540
                    PEER_TRANSACTION_LIMIT_PER_MINUTE = val;
            }
        }
        fclose(f);

        if(stat == 1)
            printf("\n");
    }
}

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

    forceWrite(".vfc/netdiff.mem", &network_difficulty, sizeof(float));
}

void loadmem()
{
    FILE* f = fopen(".vfc/peers.mem", "r");
    if(f)
    {
        if(fread(peers, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
        {
            printf("Peers Memory Corrupted. Load Failed.\n");
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
            printf("Peers1 Memory Corrupted. Load Failed.\n");
            err++;
        }
        fclose(f);
    }

    f = fopen(".vfc/peers2.mem", "r");
    if(f)
    {
        if(fread(peer_timeouts, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
        {
            printf("Peers2 Memory Corrupted. Load Failed.\n");
            err++;
        }
        fclose(f);
    }

    f = fopen(".vfc/peers3.mem", "r");
    if(f)
    {
        if(fread(peer_ua, 64, MAX_PEERS, f) != MAX_PEERS)
        {
            printf("Peers3 Memory Corrupted. Load Failed.\n");
            err++;
        }
        fclose(f);
    }

    setSeedNode();
}

uint isNodeRunning()
{
    struct sockaddr_in server;

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(s == -1)
        return 1; //Might be running, we can't risk it, say it's running

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(31963);
    
    if(bind(s, (struct sockaddr*)&server, sizeof(server)) == 0)
    {
        close(s);
        return 0; //Bind success, process not already running.
    }

    close(s);
    return 1; //Say it's running
}

void *generalThread(void *arg)
{
    if(nice(3) == -1)
        printf("ERROR: generalThread() nice(3) failed.\n");

    if(chdir(getHome()) == -1)
    {
        printf("ERROR: General Thread -1 chdir(%s)\n", getHome());
        exit(0);
    }

    //Calc difficulty
    networkDifficulty();

    //time_t rs = time(0);
    time_t sp = time(0);
    time_t nr = time(0);
    time_t pr = time(0);
    time_t aa = time(0);
    while(1)
    {
        sleep(3);

        //Save memory state
        savemem();

        //Load new replay allow values
        forceRead(".vfc/rp.mem", &replay_allow, sizeof(uint)*MAX_PEERS);

        //Recalculate network difficulty
        time_t lt = time(0);
        struct tm* tmi = gmtime(&lt);
        if(tmi->tm_min == 59 && tmi->tm_sec >= 47)
        {
            //Broadcast the top 9 transactions of both difficulty addresses
            // ensures propergation across all clients
            struct addr lpub;
            size_t len = ECC_CURVE+1;
            b58tobin(lpub.key, &len, "q15voteVFCf7Csb8dKwaYkcYVEWa2CxJVHm96SGEpvzK", 44);
            struct addr tpub;
            len = ECC_CURVE+1;
            b58tobin(tpub.key, &len, "24KvoteVFC7JsTiFaGna9F6RhtMWdB7MUa3wZoVNm7wH3", 45);
            broadcastBalance(&lpub, 9, 0);
            broadcastBalance(&tpub, 9, 0);

            //Loop until perfect time to 1 ms accuracy
            while(tmi->tm_min == 59 && tmi->tm_min != 00)
            {
                const int td = 59 - tmi->tm_sec;
                if(td != 0)
                    usleep((((td))*1000000)/15);
                lt = time(0);
                tmi = gmtime(&lt);
            }

            //It's time !!
            networkDifficulty(); //Recalculate the network difficulty

            //Update master IPv4 from DNS
            setSeedNode();
        }

        //Let's execute a Sync every 1 hour  /////  [ This should NEVER be automatic ]
        // if(time(0) > rs)
        // {
        //     //How many peers we sync off depends on the number of logical cores
        //     if(num_processors > 1)
        //         resyncBlocks(num_processors / 2);
        //     else
        //         resyncBlocks(1);
            
        //     rs = time(0) + 3600;
        // }

        //Reset peer send limit every minute
        if(time(0) > sp)
        {
            //Reset peer frequency limiting
            for(uint i = 0; i < MAX_PEERS; i++)
                peer_ltcount[i] = 0;
            
            //Update master IPv4 from DNS
            setSeedNode();

            //Load any new peers
            uint nps[MAX_PEERS];
            FILE* f = fopen(".vfc/peers.mem", "r");
            if(f)
            {
                if(fread(nps, sizeof(uint), MAX_PEERS, f) == MAX_PEERS)
                    for(uint i = 0; nps[i] != 0 && i < MAX_PEERS; i++)
                        if(getPeer(nps[i]) == -1)
                            addPeer(nps[i]);
                
                fclose(f);
            }

            //set next execution
            sp = time(0) + 60;
        }

        //Check which of the peers are still alive, those that are, update their timestamps
        if(time(0) > pr)
        {
            peersBroadcastAll(mid, 8);
            peersBroadcast("a", 1); // send user-agent too please
            //broadcastUserAgent(); //Forcibly tell everyone our user-agent
            peer_timeouts[0] = time(0) + MAX_PEER_EXPIRE_SECONDS; //Reset master timeout
            pr = time(0) + PING_INTERVAL;
        }

        /*  Every hour have the rewards address send 1 vfc to itself to authorized any possible
                new network addresses you may have been re-assigned.    */
        if(time(0) > aa)
        {
            char cmd[1024];
            sprintf(cmd, "vfc%s%s 0.001%s > /dev/null", myrewardkey, myrewardkey, myrewardkeyp);
            if(system(cmd) == -1)
                printf("ERROR: Failed to execute VFC Network Authentication.\n");
            aa = time(0) + 3600; //every hour
        }
    
    }

    return 0;
}

uint64_t g_HSEC = 0;
void *miningThread(void *arg)
{
    if(chdir(getHome()) == -1)
    {
        printf("ERROR: Mining Thread -1 chdir(%s)\n", getHome());
        exit(0);
    }
    if(nice(1) == -1) //Very high priority thread
        printf("ERROR: miningThread() nice(1) failed.\n");
    addr pub, priv;
    ecc_make_key(pub.key, priv.key);
    mval r = isSubGenesisAddressMine(pub.key); //cast
    uint64_t l = 0;
    time_t lt = time(0);
    time_t st = time(0) + 16;
    uint64_t stc = 0;
    while(1)
    {
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

        //Gen a new random addr
        ecc_make_key(pub.key, priv.key);
        const double adif = isSubDiff(pub.key);

        //Found subG?
        if(adif <= MIN_DIFFICULTY)
        {
            r = isSubGenesisAddressMine(pub.key); //cast

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
            printf("\nFound Sub-Genesis Address: \nPublic: %s\nPrivate: %s\n", bpub, bpriv);

            //Load difficulty
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));

            //Autoclaim
            if(adif <= network_difficulty)
            {
                pid_t fork_pid = fork();
                if(fork_pid == 0)
                {
                    char cmd[1024];
                    sprintf(cmd, "vfc %s%s %.3f %s > /dev/null", bpub, myrewardkey, toDB(r), bpriv);
                    if(system(cmd) == -1)
                        printf("ERROR: Failed to Execute Auto-Claim Transaction.\n");
                    exit(0);
                }
            }

            //Dump to file
            FILE* f = fopen(".vfc/minted.priv", "a");
            if(f != NULL)
            {
                flockfile(f); //lock

                fprintf(f, "%s (%.3f) (%.3f VFC)\n", bpriv, isSubDiff(pub.key), toDB(r));

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

//Transaction Processing Worker Thread
void *processThread(void *arg)
{
    if(chdir(getHome()) == -1)
    {
        printf("ERROR: Process Thread -1 chdir(%s)\n", getHome());
        exit(0);
    }

    struct trans t;
    while(1)
    {
        //See if there is a new transaction to process
        memset(&t, 0, sizeof(struct trans));
        uint32_t lip=0, lipo=0;
        unsigned char lreplay = 0;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_lock(&mutex2);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        const int i = gQue();
        if(i == -1)
        {
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex2);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            usleep(10000); // Don't thrash the CPU if there's no transactions
            continue;
        }
        lreplay = replay[i];
        lip = ip[i];
        lipo = ipo[i];
        memcpy(&t, &tq[i], sizeof(struct trans));
        tq[i].amount = 0; //Signifies transaction as invalid / completed / processed (done)
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(single_threaded == 0)
pthread_mutex_unlock(&mutex2);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //Process the transaction
        const int r = process_trans(t.uid, &t.from, &t.to, t.amount, &t.owner);

        //Possible race condition
        if(r == 1 || r == ERROR_UIDEXIST || r == ERROR_SIGFAIL)
            add_uid(t.uid, 32400); //Block for nine hours

        if(r == ERROR_NOFUNDS)
            add_uid(t.uid, 540); //Probably spam, block for 9 minutes


        // if(r == 1)
        // {
        //     if(lreplay == 0) //is replay
        //         printf("p-OK: %lu\n", t.uid);
        // }

        // if(r == ERROR_NOFUNDS)
        // {
        //     if(lreplay == 0) //is replay
        //         printf("p-NOFUNDS: %lu\n", t.uid);
        // }

        // if(r == ERROR_SIGFAIL)
        // {
        //     if(lreplay == 0) //is replay
        //         printf("p-SIGFAIL: %lu\n", t.uid);
        // }

        // if(r == ERROR_UIDEXIST)
        // {
        //     if(lreplay == 0) //is replay
        //         printf("p-UIDEXIST: %lu\n", t.uid);
        // }

        // if(r == ERROR_WRITE)
        // {
        //     if(lreplay == 0) //is replay
        //         printf("p-ERROR-WRITE: %lu\n", t.uid);
        // }

        // if(r == 1)
        // {
        //     FILE* f = fopen(".vfc/process_log.txt", "a");
        //     if(f)
        //     {
        //         flockfile(f);
        //         fprintf(f, "%lu\n", t.uid);
        //         funlockfile(f);
        //         fclose(f);
        //     }
        // }

        // if(r == ERROR_NOFUNDS)
        // {
        //     FILE* f = fopen(".vfc/process_log.txt", "a");
        //     if(f)
        //     {
        //         flockfile(f);
        //         fprintf(f, "%lu: Insufficient Ballance.\n", t.uid);
        //         funlockfile(f);
        //         fclose(f);
        //     }
        // }

        // if(r == ERROR_SIGFAIL)
        // {
        //     FILE* f = fopen(".vfc/process_log.txt", "a");
        //     if(f)
        //     {
        //         flockfile(f);
        //         fprintf(f, "%lu: Transaction signature is invalid.\n", t.uid);
        //         funlockfile(f);
        //         fclose(f);
        //     }
        // }

        // if(r == ERROR_UIDEXIST)
        // {
        //     FILE* f = fopen(".vfc/process_log.txt", "a");
        //     if(f)
        //     {
        //         flockfile(f);
        //         fprintf(f, "%lu: Transaction exists in chain.\n", t.uid);
        //         funlockfile(f);
        //         fclose(f);
        //     }
        // }

        // if(r == ERROR_WRITE)
        // {
        //     FILE* f = fopen(".vfc/process_log.txt", "a");
        //     if(f)
        //     {
        //         flockfile(f);
        //         fprintf(f, "%lu: Transaction write error.\n", t.uid);
        //         funlockfile(f);
        //         fclose(f);
        //     }
        // }

        //Good transaction!
        if(r == 1 && lreplay == 1)
        {
            //Track this client from origin
            if(getPeer(lip) == -1) //Avoid Locks and unlocks if possible
                addPeer(lip); 

            if(lipo != 0)
                if(getPeer(lipo) == -1) //Avoid Locks and unlocks if possible
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
            //triBroadcast(pc, len, 6);                       //Tell 6 peers
            peersBroadcast(pc, len);
        }

    }
    return 0;
}

//Network Processing Worker Thread
void *networkThread(void *arg)
{
    //Set directory
    if(chdir(getHome()) == -1)
    {
        printf("ERROR: Network Thread -1 chdir(%s)\n", getHome());
        exit(0);
    }

    //Vars
    struct sockaddr_in server, client;
    uint slen = sizeof(client);

    //Create socket
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(s == -1)
    {
        printf("ERROR: Network Thread Socket Creation Failed.\n");
        return 0;
    }

    //Allow the port to be reused if multi-threaded
    if(single_threaded == 0)
    {
        int reuse = 1; //mpromonet [stack overflow]
        if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed\n");
        if(setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
            perror("setsockopt(SO_REUSEPORT) failed\n");
    }

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(gport);
    
    //Bind port to socket
    while(bind(s, (struct sockaddr*)&server, sizeof(server)) < 0)
        sleep(3);

    //Never allow thread to end
    int read_size = 0;
    char rb[RECV_BUFF_SIZE];
    const uint trans_size = 1+sizeof(uint)+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
    const uint replay_size = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
    while(1)
    {
        //Client Command
        memset(rb, 0, sizeof(rb));
        read_size = recvfrom(s, rb, RECV_BUFF_SIZE-1, 0, (struct sockaddr *)&client, &slen);


        //Transaction limiter
        int peerid = -1;
        if(client.sin_addr.s_addr != inet_addr("127.0.0.1"))
        {
            peerid = getPeer(client.sin_addr.s_addr);
            if(peerid != -1)
            {
                if(peer_ltcount[peerid] >= PEER_TRANSACTION_LIMIT_PER_MINUTE)
                    continue;
            }
            else
            {
                //We allow non-peers to send one authentication request every 24 minutes per IPv4 addess.
                //Preferably we prefer new peers where added manually via an existing peer on the network.
                const uint64_t nuid = (uint64_t)client.sin_addr.s_addr;
                if(has_uid(nuid) == 0)
                    add_uid(nuid, 1600); //26 min gap between auth trans per IPv4
                else
                    continue;
            }
        }

        
        //peer has sent a transaction
        if(rb[0] == 't' && read_size == trans_size)
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
            const uint qrv = aQue(&t, client.sin_addr.s_addr, origin, 1);
            if(qrv > 0)
            {
                //printf("Q: %u %lu %u\n", t.amount, t.uid, gQueSize());

                //Log
                // char pfrom[MIN_LEN];
                // memset(pfrom, 0, sizeof(pfrom));
                // char pto[MIN_LEN];
                // memset(pto, 0, sizeof(pto));
                // size_t len = MIN_LEN;
                // b58enc(pfrom, &len, t.from.key, ECC_CURVE+1);
                // len = MIN_LEN;
                // b58enc(pto, &len, t.to.key, ECC_CURVE+1);
                // printf("%s / t: %lu, %s, %s, %u\n", inet_ntoa(client.sin_addr), t.uid, pfrom, pto, t.amount);

                //Broadcast to peers
                origin = client.sin_addr.s_addr;
                char pc[MIN_LEN];
                pc[0] = 't';
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

                //If it's a peer increase it's transaction count
                if(peerid != -1)
                {
                    peer_tcount[peerid]++; //race condition possible, however this is not a mission critical statistic
                    peer_ltcount[peerid]++;
                }

                if(qrv == 1) //Transaction Added to Que
                    triBroadcast(pc, trans_size, 3);
                else
                if(qrv == 2) //Double spend detected
                    peersBroadcast(pc, trans_size); //triBroadcast(pc, trans_size, 9);
            }
        }

        //peer is requesting a block replay
        else if(rb[0] == 'r' && read_size == 1)
        {
            //Is this peer even registered? if not, suspect foul play, not part of verified network.
            if(peerid != 1)
            {
                //Launch replay
                launchReplayThread(client.sin_addr.s_addr);
            }
        }

        //peer is requesting your user agent
        else if(rb[0] == 'a' && rb[1] == 0x00 && read_size == 1)
        {
            //Check this is the replay peer
            if(peerid != -1)
            {
                struct stat st;
                const int sr = stat(CHAIN_FILE, &st);
                if(sr == 0)
                {
                    struct utsname ud;
                    uname(&ud);
                    
                    if(st.st_size > 0)
                    {
                        char pc[MIN_LEN];
                        snprintf(pc, sizeof(pc), "a%lu, %s, %u, %s, %.3f", st.st_size / sizeof(struct trans), version, num_processors, ud.machine, node_difficulty);
                        csend(client.sin_addr.s_addr, pc, strlen(pc));
                    }
                }
            }
        }

        //peer is sending it's user agent
        else if(rb[0] == 'a' && read_size >= 9)
        {
            //Check this is a peer
            if(peerid != -1)
            {
                //printf("%s: %s\n", inet_ntoa(client.sin_addr), rb);
                memset(peer_ua[peerid], 0, 64);
                memcpy(&peer_ua[peerid], rb+1, read_size);
                peer_ua[peerid][63] = 0x00;
            }
        }

        //the replay peer is setting block height
        else if(rb[0] == 'h' && read_size == sizeof(uint)+1)
        {
            //Check if this peer is authorized to send replay transactions
            uint allow = 0;
            if(isSeedNode(client.sin_addr.s_addr) == 1)
            {
                allow = 1;
            }
            else
            {
                for(uint i = 0; replay_allow[i] != 0 && i < MAX_PEERS; i++)
                {
                    if(client.sin_addr.s_addr == replay_allow[i])
                        allow = 1;
                }
            }

            if(allow == 1)
            {
                uint32_t trh = 0;
                memcpy(&trh, rb+1, sizeof(uint)); //Set the block height
                if(trh > replay_height)
                    replay_height = trh;
                forceWrite(".vfc/rph.mem", &replay_height, sizeof(uint));
            }
        }

        //peer is sending a replay block
        else if(rb[0] == 'p' && read_size == replay_size)
        {
            //Check if this peer is authorized to send replay transactions
            uint allow = 0;
            if(isSeedNode(client.sin_addr.s_addr) == 1)
            {
                allow = 1;
            }
            else
            {
                for(uint i = 0; replay_allow[i] != 0 && i < MAX_PEERS; i++)
                {
                    if(client.sin_addr.s_addr == replay_allow[i])
                        allow = 1;
                }
            }

            if(allow == 1)
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

                //Log
                // char pfrom[MIN_LEN];
                // memset(pfrom, 0, sizeof(pfrom));
                // char pto[MIN_LEN];
                // memset(pto, 0, sizeof(pto));
                // size_t len = MIN_LEN;
                // b58enc(pfrom, &len, t.from.key, ECC_CURVE+1);
                // len = MIN_LEN;
                // b58enc(pto, &len, t.to.key, ECC_CURVE+1);
                // printf("%s / p: %lu, %s, %s, %u\n", inet_ntoa(client.sin_addr), t.uid, pfrom, pto, t.amount);

                //Alright process it, if it was a legitimate transaction we retain it in our chain.
                aQue(&t, 0, 0, 0);
                
            }
        }

        //Anon is IPv4 scanning for peers: tell Anon we exist but send our mid code, if Anon responds with our mid code we add Anon as a peer
        else if(rb[0] == '\t' && read_size == sizeof(mid))
        {
            rb[0] = '\r';
            csend(client.sin_addr.s_addr, rb, read_size);
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
                int p = addPeer(client.sin_addr.s_addr);
                if(p != -1)
                    peer_rm[p] = time(0);
            }
        }

        //A peer is requesting the nodes rewards public key
        else if(rb[0] == 'x' && read_size == 1)
        {
            if(peerid != -1)
                csend(client.sin_addr.s_addr, myrewardkey, strlen(myrewardkey));
        }
    
    }

    return 0;
}




//repair chain
void truncate_at_error(const char* file, const size_t num)
{
    int f = open(file, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);
        if(len == 0)
        {
            close(f);
            return;
        }

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

            struct trans t;
            time_t st = time(0);
            for(size_t i = sizeof(struct trans)*((len/sizeof(struct trans))-num); i < len; i += sizeof(struct trans))
            {
                memcpy(&t, m+i, sizeof(struct trans));

                if(time(0) > st && i > 0)
                {
                    printf("head: %li / %li\n", i/sizeof(struct trans), len/sizeof(struct trans));
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


/*
    This is a function that scans through the whole local chain, and removes and list 'probable' duplicates then saving
    the new chain to .vfc/cblocks.dat

    Due to the use of a hashmap with collision potential, it is recommended that operators actually investigate if the reported
    `pDUP`'s or `probably duplicate` results are actually really duplicated by using command such as `vfc out` and `vfc all`
    for analysis.

    If there is a significant amount of duplicate transactions, which is only a risk in multi-threaded mode, then you can
    look at replacing blocks.dat with cblocks.dat and the running a `vfc sync 300` to resync the missing transactions that
    where indeed unique.

    Or manually replay them.

    I should note that rather than freak out over the concept of duplicate transactions in multi-threaded mode, that this
    release has been rigorously tested against duplicate writes to blocks.dat and to which none where recorded over a seven
    day period.

    Some tips to prevent accidentally creating race conditions:
    1. Do not fork this process after checking argv inputs and executing the runtime threads.
    2. Do not launch this process mutliple times, although the compile.sh creates a 6 minute cron as a "backup" this is
        a quick and dirty solution, if the isNodeRunning() function where to ever fail, which I cannot guarentee your
        network adaptor will always play nicely using ports as a process mutex. Generally speaking ... you should be alright.
    3. Obviously lock and unlock where necessary.

    If still in doubt, here are the functions to perform the analysis which will allow you to identify if a transaction
    has been saved to the blocks.dat more than once under the same UID.

    cleanChain() - Fast pDUP check
    cleanChainFull() - Slow but 100% accurate chain rebuild, single pass.
*/
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
    //Init hashmap
    init_sites(433024253); //3,464 mb = 54,128,031 sites = 18,042,677 transactions before unsafe collision potential
    
    //Now clean the chain
    int f = open(CHAIN_FILE, O_RDONLY);
    if(f)
    {
        const size_t len = lseek(f, 0, SEEK_END);

        unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
        if(m != MAP_FAILED)
        {
            close(f);

            struct trans t;
            for(size_t i = sizeof(struct trans); i < len; i += sizeof(struct trans))
            {
                //Copy transaction
                memcpy(&t, m+i, sizeof(struct trans));

                if(has_uid(t.uid) == 1) //Probable duplicate
                {
                    char from[MIN_LEN];
                    memset(from, 0, sizeof(from));
                    size_t len = MIN_LEN;
                    b58enc(from, &len, t.from.key, ECC_CURVE+1);

                    char to[MIN_LEN];
                    memset(to, 0, sizeof(from));
                    size_t len2 = MIN_LEN;
                    b58enc(to, &len2, t.to.key, ECC_CURVE+1);

                    char sig[MIN_LEN];
                    memset(sig, 0, sizeof(sig));
                    size_t len3 = MIN_LEN;
                    b58enc(sig, &len3, t.owner.key, ECC_CURVE*2);

                    setlocale(LC_NUMERIC, "");
                    printf("pDUP: %lu, %s, %s, %s, %.3f\n", t.uid, from, to, sig, toDB(t.amount));
                    continue;
                }

                //Ok let's write the transaction to chain
                if(memcmp(t.from.key, t.to.key, ECC_CURVE+1) != 0) //Only log if the user was not sending VFC to themselves.
                {
                    FILE* f = fopen(".vfc/cblocks.dat", "a");
                    if(f)
                    {
                        fwrite(&t, sizeof(struct trans), 1, f);
                        add_uid(t.uid, 172800); //48 hours
                        fclose(f);
                    }
                }
            }

            munmap(m, len);
        }

        close(f);
    }
}
void cleanChainFull()
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
            for(size_t i = sizeof(struct trans); i < len; i += sizeof(struct trans))
            {
                //Copy transaction
                memcpy(&t, m+i, sizeof(struct trans));

                // //Verify
                // struct trans nt;
                // memset(&nt, 0, sizeof(struct trans));
                // nt.uid = t.uid;
                // memcpy(nt.from.key, t.from.key, ECC_CURVE+1);
                // memcpy(nt.to.key, t.to.key, ECC_CURVE+1);
                // nt.amount = t.amount;
                // uint8_t thash[ECC_CURVE];
                // makHash(thash, &nt);
                // if(ecdsa_verify(nt.from.key, thash, t.owner.key) == 0)
                // {
                //     printf("%lu: no verification\n", t.uid);
                //     continue;
                // }
                // //
                
                //Check has balance and is unique
                int hbr = 0;
                int64_t rv = isSubGenesisAddress(t.from.key, 1);
                f = open(".vfc/cfblocks.dat", O_RDONLY);
                if(f)
                {
                    const size_t len = lseek(f, 0, SEEK_END);

                    unsigned char* m = mmap(NULL, len, PROT_READ, MAP_SHARED, f, 0);
                    if(m != MAP_FAILED)
                    {
                        close(f);

                        struct trans tn;
                        for(size_t i = 0; i < len; i += sizeof(struct trans))
                        {
                            if(tn.uid == t.uid)
                            {
                                hbr = ERROR_UIDEXIST;
                                munmap(m, len);
                                break;
                            }
                            memcpy(&tn, m+i, sizeof(struct trans));

                            if(memcmp(&tn.to.key, &t.from.key, ECC_CURVE+1) == 0)
                                rv += tn.amount;
                            else if(memcmp(&tn.from.key, &t.from.key, ECC_CURVE+1) == 0)
                                rv -= tn.amount;
                        }

                        munmap(m, len);
                    }

                    close(f);
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
                    char from[MIN_LEN];
                    memset(from, 0, sizeof(from));
                    size_t len = MIN_LEN;
                    b58enc(from, &len, t.from.key, ECC_CURVE+1);

                    char to[MIN_LEN];
                    memset(to, 0, sizeof(from));
                    size_t len2 = MIN_LEN;
                    b58enc(to, &len2, t.to.key, ECC_CURVE+1);

                    char sig[MIN_LEN];
                    memset(sig, 0, sizeof(sig));
                    size_t len3 = MIN_LEN;
                    b58enc(sig, &len3, t.owner.key, ECC_CURVE*2);

                    setlocale(LC_NUMERIC, "");
                    printf("noBalance: %lu, %s, %s, %s, %.3f\n", t.uid, from, to, sig, toDB(t.amount));
                    continue;
                }
                else if(hbr < 0)
                {
                    char from[MIN_LEN];
                    memset(from, 0, sizeof(from));
                    size_t len = MIN_LEN;
                    b58enc(from, &len, t.from.key, ECC_CURVE+1);

                    char to[MIN_LEN];
                    memset(to, 0, sizeof(from));
                    size_t len2 = MIN_LEN;
                    b58enc(to, &len2, t.to.key, ECC_CURVE+1);

                    char sig[MIN_LEN];
                    memset(sig, 0, sizeof(sig));
                    size_t len3 = MIN_LEN;
                    b58enc(sig, &len3, t.owner.key, ECC_CURVE*2);

                    setlocale(LC_NUMERIC, "");
                    printf("uidExists: %lu, %s, %s, %s, %.3f\n", t.uid, from, to, sig, toDB(t.amount));
                    continue;
                }
                //

                //Ok let's write the transaction to chain
                if(memcmp(t.from.key, t.to.key, ECC_CURVE+1) != 0) //Only log if the user was not sending VFC to themselves.
                {
                    FILE* f = fopen(".vfc/cfblocks.dat", "a");
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


//https://stackoverflow.com/questions/77005/how-to-automatically-generate-a-stacktrace-when-my-program-crashes
void exception_handler(int sig)
{
    void *array[10];
    size_t size;
    size = backtrace(array, 10);
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

void sigint_handler(int sig_num) 
{
    static int m_qe = 0;
    
    if(m_qe == 0)
    {
        printf("\nPlease Wait while the peers state is saved...\n\n");
        m_qe = 1;

        savemem();
        exit(0);
    }
}

int main(int argc , char *argv[])
{
    //Suppress Sigpipe
    signal(SIGPIPE, SIG_IGN);

    //Handle SIGSEV
    signal(SIGSEGV, exception_handler);

    //set local working directory
    if(chdir(getHome()) == -1)
    {
        printf("ERROR: Main Process -1 chdir(%s)\n", getHome());
        exit(0);
    }

    //Workout size of server for replay scaling
    num_processors = get_nprocs();
    nthreads = num_processors;
    if(nthreads > 2)
        max_replay_threads = 8*(nthreads-2);

    //Load the config file
    loadConfig(0);
    uint command_skip = 0;

    //Make sure max_replay_threads value is limited by the buff size
    if(max_replay_threads > MAX_THREADS_BUFF)
        max_replay_threads = MAX_THREADS_BUFF;

    // < Peer arrays do not need initilisation > .. (apart from this one)
    for(uint i = 0; i < MAX_PEERS; i++)
        peer_rm[i] = time(0);

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
        makAddr(&pub, &priv, 1);

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
            printf("Failed to load Rewards address, you will be unable to receive rewards.\n");

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
            printf("Failed to load Rewards address private key, automatic network authentication will no longer be operational.\n");

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

    //Set the MID
    mid[0] = '\t';
    mid[1] = qRand(0, 255);
    mid[2] = qRand(0, 255);
    mid[3] = qRand(0, 255);
    mid[4] = qRand(0, 255);
    mid[5] = qRand(0, 255);
    mid[6] = qRand(0, 255);
    mid[7] = qRand(0, 255);

    if(argc == 6)
    {
        //Gen new address
        if(strcmp(argv[1], "new") == 0)
        {
            uint64_t l_private[4];

            sscanf(argv[2], "%lu", &l_private[0]);
            sscanf(argv[3], "%lu", &l_private[1]);
            sscanf(argv[4], "%lu", &l_private[2]);
            sscanf(argv[5], "%lu", &l_private[3]);

            addr pub, priv;

            //Make key pair
            makAddrSeed(&pub, &priv, l_private);

            exit(0);
        }
    }

    //quick send
    if(argc == 4)
    {
        if(strcmp(argv[1], "qsend") == 0)
        {
            char cmd[1024];
            snprintf(cmd, sizeof(cmd), "vfc%s %s %.3f%s", myrewardkey, argv[3], atof(argv[2]), myrewardkeyp);
            if(system(cmd) == -1)
                printf("ERROR: Failed to execute qsend.\n");
            
            exit(0);
        }

        if(strstr(argv[1], "printtrans") != NULL)
        {
            uint from;
            sscanf(argv[2], "%u", &from);

            uint to;
            sscanf(argv[3], "%u", &to);
            printtrans(from, to);
            exit(0);
        }

        if(strstr(argv[1], "top") != NULL)
        {
            addr a;
            size_t len = ECC_CURVE+1;
            b58tobin(a.key, &len, argv[2], strlen(argv[2]));
            printTop(&a, atoi(argv[3]));
            exit(0);
        }
    }

    //Outgoings and Incomings
    if(argc == 3)
    {
        //claim minted.priv
        if(strcmp(argv[1], "claim") == 0)
        {
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));
            printf("Please Wait...");
            fflush(stdout);
            FILE* f = fopen(argv[2], "r");
            if(f)
            {
                char bpriv[256];
                while(fgets(bpriv, 256, f) != NULL)
                {
                    for(uint i = 0; i < 256; i++)
                    {
                        if(bpriv[i] == ' ' || bpriv[i] == '\n')
                        {
                            bpriv[i] = 0x00;
                            break;
                        }
                    }

                    if(strlen(bpriv) < 16)
                        continue;

                    //priv as bytes
                    struct addr subg_priv;
                    size_t len = ECC_CURVE;
                    b58tobin(subg_priv.key, &len, bpriv, strlen(bpriv));

                    //Gen Public Key
                    struct addr subg_pub;
                    ecc_get_pubkey(subg_pub.key, subg_priv.key);

                    //Get balance of pub key
                    const double bal = toDB(getBalanceLocal(&subg_pub));
                    //const double bal = toDB(isSubGenesisAddress(subg_pub.key, 0)); // little faster

                    printf(".");
                    fflush(stdout);

                    if(bal > 0)
                    {
                        //Public Key as Base58
                        char bpub[MIN_LEN];
                        memset(bpub, 0, sizeof(bpub));
                        len = MIN_LEN;
                        b58enc(bpub, &len, subg_pub.key, ECC_CURVE+1);

                        //execute transaction
                        //printf("%s >%s : %.3f\n", bpub, myrewardkey, bal);
                        //printf("vfc %s%s %.3f %s > /dev/null\n\n", bpub, myrewardkey, bal, bpriv);
                        pid_t fork_pid = fork();
                        if(fork_pid == 0)
                        {
                            char cmd[1024];
                            snprintf(cmd, sizeof(cmd), "\nvfc %s%s %.3f %s > /dev/null", bpub, myrewardkey, bal, bpriv);
                            if(system(cmd) == -1)
                                printf("ERROR: Failed to execute subG address claim.\n");
                            exit(0);
                        }
                    }
                }
                fclose(f);
            }
            printf("\n");
            exit(0);
        }

        //Mine VFC
        if(strcmp(argv[1], "mine") == 0)
        {
            printf("\033[H\033[J");
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));

            nthreads = atoi(argv[2]);
            printf("%i Threads launched..\nMining Difficulty: %.3f\nNetwork Difficulty: %.3f\nSaving mined private keys to .vfc/minted.priv\n\nMining please wait...\n\n", nthreads, MIN_DIFFICULTY, getMiningDifficulty());

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
                else if(g_HSEC < 1000000 && g_HSEC > 0)
                    printf("kH/s: %.2f\n", (double)g_HSEC / 1000);
                else if(g_HSEC < 1000000000 && g_HSEC > 0)
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
            uint8_t p_privateKey[ECC_BYTES] = {0};
            size_t len = ECC_BYTES;
            b58tobin(p_privateKey, &len, argv[2], strlen(argv[2]));

            //Gen Public Key
            uint8_t p_publicKey[ECC_BYTES+1] = {0};
            ecc_get_pubkey(p_publicKey, p_privateKey);

            //Dump Public Key as Base58
            char bpub[MIN_LEN];
            memset(bpub, 0, sizeof(bpub));
            len = MIN_LEN;
            b58enc(bpub, &len, p_publicKey, ECC_CURVE+1);

            printf("\nPublic Key Generated\n\nPublic: %s\n\n", bpub);
            
            exit(0);
        }

        //truncate blocks file at first invalid transaction found
        if(strcmp(argv[1], "trunc") == 0)
        {
            truncate_at_error(CHAIN_FILE, atoi(argv[2]));
            exit(0);
        }

        //send raw transaction packet provided as base58 over udp
        if(strcmp(argv[1], "stp") == 0)
        {
            loadmem();
            
            char packet[147];
            size_t len = 147;
            b58tobin(packet, &len, argv[2], strlen(argv[2]));
            csend(inet_addr("127.0.0.1"), packet, len);
            peersBroadcast(packet, 147);
            exit(0);
        }

        //sync
        if(strcmp(argv[1], "sync") == 0)
        {
            loadmem();

            uint np = atoi(argv[2]);
            if(np > MAX_PEERS)
                np = MAX_PEERS;
            resyncBlocks(np);
            
            __off_t ls = 0;
            uint tc = 0;
            time_t tt = time(0);
            while(1)
            {
                struct stat st;
                stat(CHAIN_FILE, &st);
                if(st.st_size != ls)
                {
                    ls = st.st_size;
                    tc = 0;
                }

                printf("\033[H\033[J");
                if(tc > 1 || time(0) > tt)
                {
                    tc = 0;
                    resyncBlocks(np); //Sync from a new random peer if no data after x seconds
                    tt = time(0) + 33;
                }

                forceRead(".vfc/rph.mem", &replay_height, sizeof(uint));

                if(st.st_size > 0 && replay_height > 0)
                {
                    if(np == 0)
                        printf("%.1f kb of %.1f kb downloaded press CTRL+C to Quit. Synchronizing only from the Master.\n", (double)st.st_size / 1000, (double)replay_height / 1000);
                    else
                        printf("%.1f kb of %.1f kb downloaded press CTRL+C to Quit. Authorized %u Peers.\n", (double)st.st_size / 1000, (double)replay_height / 1000, np);
                }
                else
                {
                    printf("Please wait while we try to connect...\n");
                }
                

                tc++;
                sleep(1);
            }

            exit(0);
        }

        //Gen new address
        if(strcmp(argv[1], "new") == 0)
        {
            addr pub, priv;
            
            //xor down random input to 32 bytes
            const size_t len = strlen(argv[2]);
            if(len == 0)
                exit(0);

            const uint xor_chunk = len / 32;
            if(xor_chunk <= 1)
            {
                printf("You need to input a longer seed.\n");
                exit(0);
            }
            uint8_t xr[32];
            for(uint i1 = 1, io = 0; i1 < len; i1 += xor_chunk, io++)
            {
                uint8_t xc = argv[2][i1];
                for(uint i2 = 0; i2 < xor_chunk; i2++)
                    xc ^= argv[2][i1+i2];
                xr[io] = xc;
            }
            
            //Split into three uint64's
            uint64_t sp[4];
            memcpy(&sp[0], xr, sizeof(uint64_t));
            memcpy(&sp[1], xr+sizeof(uint64_t), sizeof(uint64_t));
            memcpy(&sp[2], xr+sizeof(uint64_t)+sizeof(uint64_t), sizeof(uint64_t));
            memcpy(&sp[3], xr+sizeof(uint64_t)+sizeof(uint64_t)+sizeof(uint64_t), sizeof(uint64_t));
            
            //Pass it over
            makAddrSeed(&pub, &priv, sp);
            exit(0);
        }

        if(strcmp(argv[1], "issub") == 0)
        {
            //Load difficulty
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));

            //Get Public Key
            uint8_t p_publicKey[ECC_BYTES+1];
            size_t len = ECC_CURVE+1;
            b58tobin(p_publicKey, &len, argv[2], strlen(argv[2]));

            //Dump Public Key as Base58
            const double diff = isSubDiff(p_publicKey);

            if(diff < MIN_DIFFICULTY)
                printf("subG: %s (%.3f DIFF) (%.3f VFC)\n\n", argv[2], diff, toDB(isSubGenesisAddress(p_publicKey, 1)));
            else
                printf("This is not a subGenesis (subG) Address.\n");
            
            exit(0);
        }

        if(strcmp(argv[1], "findtrans") == 0)
        {
            findTrans(strtoull(argv[2], NULL, 10));
            exit(0);
        }

        if(strcmp(argv[1], "addpeer") == 0)
        {
            loadmem();
            addPeer(inet_addr(argv[2]));
            printf("\nThank you peer %s has been added to the peer list.\n\n", argv[2]);
            savemem();
            exit(0);
        }

        if(strcmp(argv[1], "replaypeer") == 0)
        {
            const uint32_t tip = inet_addr(argv[2]);
            memset(&replay_allow, 0, sizeof(uint) * MAX_PEERS);
            replay_allow[0] = tip;
            forceWrite(".vfc/rp.mem", &replay_allow, sizeof(uint) * MAX_PEERS);
            csend(tip, "r", 1);
            printf("\nThank you peer %s has been requested to replay it's blocks.\n\nPlease make sure you are not also running sync at this time as they will conflict. (please ensure the VFC node is not running when you add new peers)\n\n", argv[2]);
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

        if(strstr(argv[1], "all") != NULL)
        {
            addr a;
            size_t len = ECC_CURVE+1;
            b58tobin(a.key, &len, argv[2], strlen(argv[2]));
            printAll(&a);
            exit(0);
        }

        //Dump top trans
        if(strcmp(argv[1], "dumptop") == 0)
        {
            struct stat st;
            stat(CHAIN_FILE, &st);
            dumptrans((st.st_size / sizeof(struct trans)) - atoi(argv[2]));
            exit(0);
        }

    }

    //Some basic funcs
    if(argc == 2)
    {
        //Help
        if(strcmp(argv[1], "help") == 0)
        {
            printf("\n-----------------------------\n");
            printf("vfc update                    - Updates node\n");
            printf("vfc <address public key>      - Get address balance\n");
            printf("vfc out <address public key>  - Gets sent transactions\n");
            printf("vfc in <address public key>   - Gets received transactions\n");
            printf("vfc all <address public key>  - Recv & Sent transactions\n");
            printf("vfc top <address> <num>       - Top Recv & Sent transactions\n");
            printf("-----------------------------\n\n");
            printf("Send a transaction:\n");
            printf("vfc <sender public key> <reciever public key> <amount> <sender private key>\n\n");
            printf("vfc makeonly <sender public key> <reciever public key> <amount> <sender private key>\n\n");
            printf("vfc sendRaw <uid> <sender public key> <reciever public key> <amount> <sig>\n\n");
            printf("--------------------------------------\n");
            printf("vfc new <optional seed>                 - Create a new Address / Key-Pair\n");
            printf("vfc new <seed1> <seed2> <seed3> <seed4> - Four random seed(uint64), Key-Pair\n");
            printf("--------------------------------------\n");
            printf("vfc qsend <amount> <receiver address>   - Send transaction from rewards address\n");
            printf("vfc claim <optional file path>          - Claims private keys to rewards addr\n");
            printf("vfc reward                              - Your awarded or mined VFC\n");
            printf("-------------------------------\n");
            printf("vfc mine <optional num threads>  - CPU miner for VFC\n");
            printf("vfc peers                        - List locally indexed living peers\n");
            printf("vfc deadpeers                    - List locally indexed dead peers\n");
            printf("vfc flushpeers                   - Removes all indexed peers\n");
            printf("vfc getpub <private key>         - Get Public Key from Private Key\n");
            printf("vfc issub <public key>           - Is supplied public address a subG address\n");
            printf("-------------------------------\n");
            printf("vfc spread                       - Map of client difficulty values\n");
            printf("vfc difficulty                   - Network mining difficulty\n");
            printf("-------------------------------\n");
            printf("vfc sync <optional num peers>    - Trigger blockchain sync from your peers\n");
            printf("vfc cdn_resync                   - Trigger blockchain resync from the master\n");
            printf("vfc reset_chain                  - Reset blockchain back to genesis state\n");
            printf("vfc scan                         - Scan for peers in the IPv4 range.\n");
            printf("-------------------------------\n");
            printf("vfc replaypeer <peer ip address> - Manually replay from specific peer\n");
            printf("vfc addpeer <peer ip address>    - Manually add a peer\n");
            printf("vfc printtrans 1000 1010         - Print transactions[start,end] on chain\n");
            printf("vfc findtrans <transaction uid>  - Find a transaction by it's UID\n");
            printf("-------------------------------\n");
            printf("vfc dump                         - List all transactions on chain\n");
            printf("vfc dumptop <num trans>          - List top x transactions on chain\n");
            printf("vfc dumpbad                      - List all detected double spend attempts\n");
            printf("vfc clearbad                     - Clear all detected double spend attempts\n");
            printf("-------------------------------\n\n");
            printf("Scan blocks.dat for invalid transactions and truncate at first detected:\nvfc trunc <offset from eof>\n\n");
            printf("[Fast] Scan blocks.dat for duplicate transactions and generates a cleaned output; cblocks.dat:\nvfc clean\n\n");
            printf("[Slow] Scan blocks.dat for invalid transactions and generates a cleaned output; cfblocks.dat:\nvfc cleanfull\n\n");
            printf("----------------\n");
            printf("vfc version      - Node version\n");
            printf("vfc agent        - Node user-agent\n");
            printf("vfc config       - Node configuration\n");
            printf("vfc high         - Returns node [ blocks.dat size / num transactions ]\n");
            printf("vfc circulating  - Circulating supply\n");
            printf("vfc minted       - Minted supply\n");
            printf("vfc unclaimed    - Lists all unclaimed addresses from your minted.priv\n");
            printf("vfc claim        - Claims the contents of minted.priv to your rewards address\n");
            printf("----------------\n");
            printf("vfc single       - Launches the VFC node as single threaded\n");
            printf("vfc multi        - Launches the VFC node as multi threaded\n");
            printf("----------------\n\n");
  
            printf("To get started running a dedicated node, execute ./vfc on a seperate screen.\n\n");
            exit(0);
        }

        //get node user agent
        if(strcmp(argv[1], "agent") == 0)
        {
            loadmem();
            forceRead(".vfc/netdiff.mem", &node_difficulty, sizeof(float));
            struct stat st;
            const int sr = stat(CHAIN_FILE, &st);
            struct utsname ud;
            uname(&ud);
            if(sr == 0 && st.st_size > 0)
                printf("%lu, %s, %u, %s, %.3f\n", st.st_size / sizeof(struct trans), version, num_processors, ud.machine, node_difficulty);
            broadcastUserAgent();
            exit(0);
        }

        //get minting difficulty
        if(strcmp(argv[1], "difficulty") == 0)
        {
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));
            printf("Average / Network Difficulty: %.3f\n", network_difficulty);

            //Vote Less than MIN_DIFFICULTY
            struct addr lpub;
            size_t len = ECC_CURVE+1;
            b58tobin(lpub.key, &len, "q15voteVFCf7Csb8dKwaYkcYVEWa2CxJVHm96SGEpvzK", 44);

            //Vote MIN_DIFFICULTY
            struct addr tpub;
            len = ECC_CURVE+1;
            b58tobin(tpub.key, &len, "24KvoteVFC7JsTiFaGna9F6RhtMWdB7MUa3wZoVNm7wH3", 45);

            time_t lt = time(0);
            struct tm* tmi = gmtime(&lt);

            printf("In order to vote you are expected to pay vfc into one of two addresses that define the minting difficulty value between [0.031 - %.3f].\n\n", MIN_DIFFICULTY);
            setlocale(LC_NUMERIC, "");
            printf("To decrease the difficulty towards 0.031 pay VFC into:\nq15voteVFCf7Csb8dKwaYkcYVEWa2CxJVHm96SGEpvzK (%'.3f VFC)\n\n", toDB(getBalanceLocal(&lpub)));
            printf("To increase the difficulty towards %.3f. pay VFC into:\n24KvoteVFC7JsTiFaGna9F6RhtMWdB7MUa3wZoVNm7wH3 (%'.3f VFC)\n\n", MIN_DIFFICULTY, toDB(getBalanceLocal(&tpub)));
            printf("If the balance of 24K~ is higher than q15~ the difficulty will be %.3f, otherwise the difference between the balance of the two addresses will be used to reduce the difficulty from %.3f to 0.031.\n\n", MIN_DIFFICULTY, MIN_DIFFICULTY);
            printf("Next Network Difficulty: %.3f in %u minutes\n", liveNetworkDifficulty(), 60 - tmi->tm_min);
            printf("Current Network Difficulty: %.3f\n\n", network_difficulty);
            
            exit(0);
        }

        //get mining difficulty
        if(strcmp(argv[1], "spread") == 0)
        {
            loadmem();
            int vpp = (countLivingPeers()*1.23)/209;
            if(vpp < 1)
                vpp = 1;
            printf("%u\n", vpp);
            printDifficultySpread();
            exit(0);
        }

        //circulating supply
        if(strcmp(argv[1], "circulating") == 0)
        {
            printf("%.3f\n", toDB(getCirculatingSupply()));
            exit(0);
        }

        //Mined VFC in circulation
        if(strcmp(argv[1], "minted") == 0)
        {
            printf("%.3f\n", toDB(getMinedSupply()));
            exit(0);
        }

        //threading options
        if(strcmp(argv[1], "single") == 0)
        {
            single_threaded = 1;
            command_skip = 1;
        }
        if(strcmp(argv[1], "multi") == 0)
        {
            single_threaded = 0;
            command_skip = 1;
        }

        //Fork unclaimed addresses from minted.priv
        if(strcmp(argv[1], "unclaimed") == 0)
        {
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));
            fflush(stdout);
            FILE* f = fopen(".vfc/minted.priv", "r");
            if(f)
            {
                char bpriv[256];
                while(fgets(bpriv, 256, f) != NULL)
                {
                    for(uint i = 0; i < 256; i++)
                    {
                        if(bpriv[i] == ' ' || bpriv[i] == '\n')
                        {
                            bpriv[i] = 0x00;
                            break;
                        }
                    }

                    if(strlen(bpriv) < 16)
                        continue;

                    //priv as bytes
                    struct addr subg_priv;
                    size_t len = ECC_CURVE;
                    b58tobin(subg_priv.key, &len, bpriv, strlen(bpriv));

                    //Gen Public Key
                    struct addr subg_pub;
                    ecc_get_pubkey(subg_pub.key, subg_priv.key);

                    //Get balance of pub key
                    const double bal = toDB(getBalanceLocal(&subg_pub));

                    //Print private key & balance 
                    if(bal > 0)
                        printf("%s (%.3f)\n", bpriv, bal);
                    
                }
                fclose(f);
            }
            exit(0);
        }

        //claim minted.priv
        if(strcmp(argv[1], "claim") == 0)
        {
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));
            printf("Please Wait...");
            fflush(stdout);
            FILE* f = fopen(".vfc/minted.priv", "r");
            if(f)
            {
                char bpriv[256];
                while(fgets(bpriv, 256, f) != NULL)
                {
                    for(uint i = 0; i < 256; i++)
                    {
                        if(bpriv[i] == ' ' || bpriv[i] == '\n')
                        {
                            bpriv[i] = 0x00;
                            break;
                        }
                    }

                    if(strlen(bpriv) < 16)
                        continue;

                    //priv as bytes
                    struct addr subg_priv;
                    size_t len = ECC_CURVE;
                    b58tobin(subg_priv.key, &len, bpriv, strlen(bpriv));

                    //Gen Public Key
                    struct addr subg_pub;
                    ecc_get_pubkey(subg_pub.key, subg_priv.key);

                    //Get balance of pub key
                    const double bal = toDB(getBalanceLocal(&subg_pub));
                    //const double bal = toDB(isSubGenesisAddress(subg_pub.key, 0)); // little faster

                    printf(".");
                    fflush(stdout);

                    if(bal > 0)
                    {
                        //Public Key as Base58
                        char bpub[MIN_LEN];
                        memset(bpub, 0, sizeof(bpub));
                        len = MIN_LEN;
                        b58enc(bpub, &len, subg_pub.key, ECC_CURVE+1);

                        //execute transaction
                        //printf("%s >%s : %.3f\n", bpub, myrewardkey, bal);
                        //printf("vfc %s%s %.3f %s > /dev/null\n\n", bpub, myrewardkey, bal, bpriv);
                        pid_t fork_pid = fork();
                        if(fork_pid == 0)
                        {
                            char cmd[1024];
                            snprintf(cmd, sizeof(cmd), "\nvfc %s%s %.3f %s > /dev/null", bpub, myrewardkey, bal, bpriv);
                            if(system(cmd) == -1)
                                printf("ERROR: Failed to execute subG address claim.\n");
                            exit(0);
                        }
                    }
                }
                fclose(f);
            }
            printf("\n");
            exit(0);
        }

        //version
        if(strcmp(argv[1], "version") == 0)
        {
            printf("%s\n", version);
            exit(0);
        }

        //config
        if(strcmp(argv[1], "config") == 0)
        {
            loadConfig(1);
            exit(0);
        }

        //Updates installed client from official git
        if(strcmp(argv[1], "update") == 0)
        {
            printf("Please run this command with sudo or sudo -s, aka sudo vfc update\n");
            if(system("rm -r -f VFC-Core") != -1)
                if(system("git clone https://github.com/vfcash/VFC-Core") != -1)
                    if(chdir("VFC-Core") != -1)
                        if(system("chmod 0777 compile.sh") != -1)
                            if(system("./compile.sh") != -1)
                                exit(0);
            exit(0);
        }

        //Block height / total blocks / size
        if(strcmp(argv[1], "high") == 0)
        {
            struct stat st;
            const int sr = stat(CHAIN_FILE, &st);
            if(sr == 0 && st.st_size > 0)
                printf("%.0f kb (%.2f gb) / %lu Transactions\n", (double)st.st_size / 1000, ((((double)st.st_size) / 1000) / 1000) / 1000, st.st_size / sizeof(struct trans));
            exit(0);
        }

        //Mine VFC
        if(strcmp(argv[1], "mine") == 0)
        {
            printf("\033[H\033[J");
            forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));

            nthreads = get_nprocs();
            printf("%i CPU Cores detected..\nMining Difficulty: %.3f\nNetwork Difficulty: %.3f\nSaving mined private keys to .vfc/minted.priv\n\nMining please wait...\n\n", nthreads, MIN_DIFFICULTY, getMiningDifficulty());
            

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
                else if(g_HSEC < 1000000 && g_HSEC > 0)
                    printf("kH/s: %.2f\n", (double)g_HSEC / 1000);
                else if(g_HSEC < 1000000000 && g_HSEC > 0)
                    printf("mH/s: %.2f\n", (double)g_HSEC / 1000000);
            }
            
            //only exits on sigterm
            exit(0);
        }

        //sync
        if(strcmp(argv[1], "sync") == 0)
        {
            loadmem();

            resyncBlocks(33);
            
            __off_t ls = 0;
            uint tc = 0;
            time_t tt = time(0);
            while(1)
            {
                struct stat st;
                stat(CHAIN_FILE, &st);
                if(st.st_size != ls)
                {
                    ls = st.st_size;
                    tc = 0;
                }

                printf("\033[H\033[J");
                if(tc > 1 || time(0) > tt)
                {
                    tc = 0;
                    resyncBlocks(33); //Sync from a new random peer if no data after x seconds
                    tt = time(0) + 33;
                }

                forceRead(".vfc/rph.mem", &replay_height, sizeof(uint));

                if(st.st_size > 0 && replay_height > 0)
                {
                    if(replay_allow[0] == 0)
                        printf("%.1f kb of %.1f kb downloaded press CTRL+C to Quit. Synchronizing only from the Master.\n", (double)st.st_size / 1000, (double)replay_height / 1000);
                    else
                        printf("%.1f kb of %.1f kb downloaded press CTRL+C to Quit.\n", (double)st.st_size / 1000, (double)replay_height / 1000);
                }
                else
                {
                    printf("Please wait while we try to connect...\n");
                }

                tc++;
                sleep(1);
            }

            exit(0);
        }

        //master_resync
        if(strcmp(argv[1], "master_resync") == 0 || strcmp(argv[1], "cdn_resync") == 0)
        {
            remove(CHAIN_FILE);

            printf("Please select a mirror: 1 or 2: ");
            char c;
            if(scanf("%c", &c) > 0)
            {
                if(c == '1')
                    if(system("wget -O.vfc/master_blocks.dat http://vfcash.co.uk/sync/") != -1)
                        if(system("cp .vfc/master_blocks.dat .vfc/blocks.dat") != -1)
                            printf("Resync from master complete.\n\n");

                if(c == '2')
                    if(system("wget -O.vfc/master_blocks.dat http://207.180.252.56:8000/master_blocks.dat") != -1)
                        if(system("cp .vfc/master_blocks.dat .vfc/blocks.dat") != -1)
                            printf("Resync from master complete.\n\n");
            }

            exit(0);
        }

        //resync
        if(strcmp(argv[1], "reset_chain") == 0)
        {
            makGenesis(); //Erases chain and resets it for a full resync
            loadmem();
            printf("Chain Reset.\n\n");
            exit(0);
        }

        //Gen new address
        if(strcmp(argv[1], "new") == 0)
        {
            addr pub, priv;
            makAddr(&pub, &priv, 0);
            exit(0);
        }

        //Scan for peers
        if(strcmp(argv[1], "scan") == 0)
        {
            if(isNodeRunning() == 0)
            {
                printf("The VFC node needs to be running before you scan for peers.\n\n");
                exit(0);
            }

            loadmem();
            scanPeers();
            savemem();
            exit(0);
        }

        //Dump all trans
        if(strcmp(argv[1], "dump") == 0)
        {
            dumptrans(0);
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

        //Create a cleaned chain
        if(strcmp(argv[1], "cleanfull") == 0)
        {
            newClean();
            cleanChainFull();
            exit(0);
        }

        //Return reward addr
        if(strcmp(argv[1], "reward") == 0)
        {
            loadmem();

            addr rk;
            size_t len = ECC_CURVE+1;
            b58tobin(rk.key, &len, myrewardkey+1, strlen(myrewardkey)-1); //It's got a space in it (at the beginning) ;)

            const uint64_t bal = getBalanceLocal(&rk);

            setlocale(LC_NUMERIC, "");
            printf("Your reward address is:%s\nFinal Balance: %'.3f VFC\n\n", myrewardkey, toDB(bal));
            exit(0);
        }

        //Force add a peer
        if(strcmp(argv[1], "addpeer") == 0)
        {
            loadmem();
            printf("Please input Peer IP Address: ");
            char in[32];
            if(fgets(in, 32, stdin) != NULL)
            {
                addPeer(inet_addr(in));
                printf("\nThank you peer %s has been added to the peer list.\n\n", in);
                savemem();
            }
            exit(0);
        }

        //Remove all peers
        if(strcmp(argv[1], "flushpeers") == 0)
        {
            printf("Peers flushed. Please ensure the VFC Node is not running when executing this command.\n");
            remove(".vfc/peers.mem");
            remove(".vfc/peers1.mem");
            remove(".vfc/peers2.mem");
            remove(".vfc/peers3.mem");
            exit(0);
        }

        //List alive peers and their total throughput
        if(strcmp(argv[1], "peers") == 0)
        {
            loadmem();
            printf("\nTip; If you are running a full-node then consider hosting a website on port 80 where you can declare a little about your operation and a VFC address people can use to donate to you on. Thus you should be able to visit any of these IP addresses in a web-browser and find out a little about each node or obtain a VFC Address to donate to the node operator on.\n\n");
            printf("Total Peers: %u\n\n", num_peers);
            printf("IP Address / Number of Transactions Relayed / Seconds since last trans or ping / user-agent [blockheight/version/cpu cores/machine/difficulty] \n");
            uint ac = 0;
            for(uint i = 0; i < num_peers; ++i)
            {
                struct in_addr ip_addr;
                ip_addr.s_addr = peers[i];
                const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS);
                if(isPeerAlive(i) == 1 || i == 0)
                {
                    printf("%s / %u / %u / %s\n", inet_ntoa(ip_addr), peer_tcount[i], pd, peer_ua[i]);
                    ac++;
                }
            }
            printf("Alive Peers: %u\n\n", ac);
            exit(0);
        }

        //List dead peers and their total throughput
        if(strcmp(argv[1], "deadpeers") == 0)
        {
            loadmem();
            printf("\nTip; If you are running a full-node then consider hosting a website on port 80 where you can declare a little about your operation and a VFC address people can use to donate to you on. Thus you should be able to visit any of these IP addresses in a web-browser and find out a little about each node or obtain a VFC Address to donate to the node operator on.\n\n");
            printf("Total Peers: %u\n\n", num_peers);
            printf("IP Address / Number of Transactions Relayed / Seconds since last trans or ping / user-agent [blockheight/version/cpu cores/machine/difficulty] \n");
            uint ac = 0;
            for(uint i = 0; i < num_peers; ++i)
            {
                struct in_addr ip_addr;
                ip_addr.s_addr = peers[i];
                const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS);
                if(isPeerAlive(i) == 0)
                {
                    printf("%s / %u / %u / %s\n", inet_ntoa(ip_addr), peer_tcount[i], pd, peer_ua[i]);
                    ac++;
                }
            }
            printf("Dead Peers: %u\n\n", ac);
            exit(0);
        }
    }

    //Let's make sure we're on the correct chain
    if(verifyChain(CHAIN_FILE) == 0)
    {
        printf("Invalid chain. Please run ./vfc reset_chain & ./vfc sync or ./vfc cdn_resync\n\n");
        if(system("vfc cdn_resync") == -1)
            exit(0);
        exit(0);
    }

    //Init arrays
    memset(peers, 0, sizeof(uint)*MAX_PEERS);
    memset(peer_timeouts, 0, sizeof(uint)*MAX_PEERS);

    memset(&thread_ip, 0, sizeof(uint)*max_replay_threads);
    memset(&tq, 0, sizeof(struct trans)*MAX_TRANS_QUEUE);
    memset(&ip, 0, sizeof(uint)*MAX_TRANS_QUEUE);
    memset(&ipo, 0, sizeof(uint)*MAX_TRANS_QUEUE);
    memset(&replay, 0, sizeof(unsigned char)*MAX_TRANS_QUEUE);
    memset(&delta, 0, sizeof(time_t)*MAX_TRANS_QUEUE);

    //Load Mem
    loadmem();

    //Does user just wish to get address balance?
    if(argc == 2 && command_skip == 0)
    {
        //Load difficulty
        forceRead(".vfc/netdiff.mem", &network_difficulty, sizeof(float));

        //Get balance
        addr from;
        size_t len = ECC_CURVE+1;
        b58tobin(from.key, &len, argv[1], strlen(argv[1]));

        //Local
        struct timespec s;
        clock_gettime(CLOCK_MONOTONIC, &s);
        uint64_t bal = getBalanceLocal(&from);
        struct timespec e;
        clock_gettime(CLOCK_MONOTONIC, &e);
        time_t td = (e.tv_nsec - s.tv_nsec);
        if(td > 0){td /= 1000000;}
        else if(td < 0){td = 0;}
        
        //Result
        setlocale(LC_NUMERIC, "");
        printf("The Balance for Address: %s\nTime Taken %li Milliseconds (%li ns).\n\nFinal Balance: %'.3f VFC\n\n", argv[1], td, (e.tv_nsec - s.tv_nsec), toDB(bal));
        exit(0);
    }

    if(argc == 6)
    {
        // ./vfc makeonly <sender public key> <reciever public key> <amount> <sender private key>
        if(strcmp(argv[1], "makeonly") == 0)
        {
            uint8_t from[ECC_CURVE+1];
            uint8_t to[ECC_CURVE+1];
            uint8_t priv[ECC_CURVE];
            //
            size_t blen = ECC_CURVE+1;
            b58tobin(from, &blen, argv[2], strlen(argv[2]));
            b58tobin(to, &blen, argv[3], strlen(argv[3]));
            blen = ECC_CURVE;
            b58tobin(priv, &blen, argv[5], strlen(argv[5]));

            const mval sbal = fromDB(atof(argv[4]));

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
                printf("The amount you provided was too low, please try 0.001 VFC or above.\n\n");
                exit(0);
            }
            //UID Based on timestamp & signature
            time_t ltime = time(NULL);
            char suid[MIN_LEN];
            snprintf(suid, sizeof(suid), "%s/%s", asctime(localtime(&ltime)), argv[2]); //timestamp + base58 from public key
            t.uid = crc64(0, (unsigned char*)suid, strlen(suid));

            //Sign the block
            uint8_t thash[ECC_CURVE];
            makHash(thash, &t);
            if(ecdsa_sign(priv, thash, t.owner.key) == 0)
            {
                printf("\nTransaction signing failed.\n\n");
                exit(0);
            }

            char sig[MIN_LEN];
            memset(sig, 0, sizeof(sig));
            size_t len3 = MIN_LEN;
            b58enc(sig, &len3, t.owner.key, ECC_CURVE*2);

            setlocale(LC_NUMERIC, "");
            //printf("%lu: %s > %'.3f\n", t.uid, pub, toDB(t.amount));
            printf("Success.\nUid: %lu\nFrom: %s\nTo: %s\nOwner: %s\nAmount: %.3f\n", t.uid, argv[2], argv[3], sig, toDB(t.amount));

            exit(0);
        }
    }

    if(argc == 7)
    {
        // ./vfc sendRaw <uid> <sender public key> <reciever public key> <amount> <sig>
        if(strcmp(argv[1], "sendRaw") == 0)
        {

            uint8_t from[ECC_CURVE+1];
            uint8_t to[ECC_CURVE+1];
            uint8_t owner[ECC_CURVE*2];
            //
            size_t blen = ECC_CURVE+1;
            b58tobin(from, &blen, argv[3], strlen(argv[3]));
            b58tobin(to, &blen, argv[4], strlen(argv[4]));
            size_t slen = ECC_CURVE*2;
            b58tobin(owner, &slen, argv[6], strlen(argv[6]));

            const mval sbal = fromDB(atof(argv[5]));

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
                printf("Sorry the amount you provided was too low, please try 0.001 VFC or above.\n\n");
                exit(0);
            }
            sscanf(argv[2], "%lu", &t.uid);

            //Sign the block
            uint8_t thash[ECC_CURVE];
            makHash(thash, &t);
            if(ecdsa_verify(t.from.key, thash, owner) == 0)
            {
                printf("\nFailed to verify the Transaction.\n\n");
                exit(0);
            }

            memcpy(t.owner.key, owner, ECC_CURVE*2);
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
            peersBroadcast(pc, len);

            printf("Success.\n");
            exit(0);
        }
    }


    //GET TRANS HASH
    if(argc == 6)
    {
        //Recover data from parameters
        uint8_t from[ECC_CURVE+1];
        uint8_t to[ECC_CURVE+1];
        size_t blen = ECC_CURVE+1;
        b58tobin(from, &blen, argv[1], strlen(argv[1]));
        b58tobin(to, &blen, argv[2], strlen(argv[2]));
        const mval sbal = fromDB(atof(argv[3]));
        
        //Construct Transaction
        struct trans t;
        memset(&t, 0, sizeof(struct trans));
        memcpy(t.from.key, from, ECC_CURVE+1);
        memcpy(t.to.key, to, ECC_CURVE+1);
        t.amount = sbal;
        t.uid = strtoull(argv[4], NULL, 10);

        //Sign the block
        uint8_t thash[ECC_CURVE];
        makHash(thash, &t);

        char bhash[MIN_LEN];
        memset(bhash, 0, sizeof(bhash));
        size_t zlen = MIN_LEN;
        b58enc(bhash, &zlen, thash, ECC_CURVE);
        printf("%s\n", bhash);
        exit(0);
    }

    //EXECT TRANS | EXECUTE TRANSACTION
    if(argc == 5)
    {
    //Force console to clear.
    printf("\033[H\033[J");

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
            printf("Sorry the amount you provided was too low, please try 0.001 VFC or above.\n\n");
            exit(0);
        }

    //Get balance..
    const int64_t bal0 = getBalanceLocal(&t.from);

        //UID Based on timestamp & signature
        time_t ltime = time(NULL);
        char suid[MIN_LEN];
        snprintf(suid, sizeof(suid), "%s/%s", asctime(localtime(&ltime)), argv[1]); //timestamp + base58 from public key
        t.uid = crc64(0, (unsigned char*)suid, strlen(suid));

        //Sign the block
        uint8_t thash[ECC_CURVE];
        makHash(thash, &t);
        if(ecdsa_sign(priv, thash, t.owner.key) == 0)
        {
            printf("\nSorry your client failed to sign the Transaction.\n\n");
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
        peersBroadcast(pc, len);

        //Log
        char howner[MIN_LEN];
        memset(howner, 0, sizeof(howner));
        size_t zlen = MIN_LEN;
        b58enc(howner, &zlen, t.owner.key, ECC_CURVE);

        printf("\nPacket Size: %lu. %'.3f VFC. Sending Transaction...\n", len, (double)t.amount / 1000);
        printf("%lu: %s > %s : %u : %s\n", t.uid, argv[1], argv[2], t.amount, howner);
        printf("Transaction Sent.\n\n");

        //Wait before getting balance again..
        sleep(3);

//////////////////////////////////////////
//Loop until send confirmed atleast locally
//////////////////////////////////////////
time_t mtt = time(0)+33;
while(1)
{
        if(time(0) > mtt)
        {
            printf("Transaction Sent, but unable to verify it's success. Refer to sent transactions for confirmation. Ending...\n\n");
            break;
        }

        const int64_t bal1 = getBalanceLocal(&t.from);
        setlocale(LC_NUMERIC, "");
        if(bal0 == bal1)
        {
            printf("Transaction Sent, but unable to verify it's success. Refer to sent transactions for confirmation. Trying again..\n\n");
            csend(inet_addr("127.0.0.1"), pc, len); //Will attempt local cache.
            peersBroadcast(pc, len); //And an additional peers broadcast
            sleep(1);
        }
        else
        {
            printf("VFC Sent: %'.3f VFC\n\n", toDB(t.amount));
            break;
        }
}
//////////////////////////////////////////

        //Done
        exit(0);
    }

    //How did we get here?
    if(argc > 1 && command_skip == 0)
    {
        //Looks like some unknown command was executed.
        printf("Command not recognised.\n");
        exit(0);
    }

    //Don't run a node twice
    if(isNodeRunning() == 1)
    {
        printf("The VFC node is already running.\n\n");
        exit(0);
    }
    

    //Check for broken blocks
    printf("Quick Scan: Checking blocks.dat for invalid transactions...\n");
    truncate_at_error(CHAIN_FILE, 9333);

    //Callback for CTRL+C
    signal(SIGINT, sigint_handler);
    
    //Init UID hashmap
    init_sites(MAX_SITES); //11 mb


    //Launch Info
    timestamp();
    printf("\n.. VFC ..\n");
    printf("https://VFCASH.UK\n");
    printf("https://github.com/vfcash\n");
    printf("v%s\n\n", version);
    printf("You will have to make a transaction before your IPv4 address registers\nwith the mainnet when running a full time node/daemon.\n\n");
    printf("To get a full command list use:\n ./vfc help\n\n");
    char cwd[MIN_LEN];
    if(getcwd(cwd, sizeof(cwd)) != NULL)
        printf("Current Directory: %s\n\n", cwd);

    //Decide if single or multi-threaded
    nthreads = get_nprocs();
    if(single_threaded == 1)
        nthreads = 1;
    
    //Launch the Transaction Processing threads
    for(int i = 0; i < nthreads; i++)
    {
        pthread_t tid;
        if(pthread_create(&tid, NULL, processThread, NULL) != 0)
            continue;
    }

    //Launch the Network Processing threads
    for(int i = 0; i < nthreads; i++)
    {
        pthread_t tid;
        if(pthread_create(&tid, NULL, networkThread, NULL) != 0)
            continue;
    }

    //Launch the General Processing thread
    pthread_t tid2;
    pthread_create(&tid2, NULL, generalThread, NULL);


    //Loop, until sigterm
    struct sockaddr_in server;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(s == -1)
        return 0;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(31963);
    if(bind(s, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        printf("Sorry the port %u seems to already be in use. Daemon must already be running, good bye.\n\n", gport);
        exit(0);
    }
    printf("Waiting for connections...\n\n");
    time_t tt = time(0);
    while(1)
    {
        setlocale(LC_NUMERIC, "");
        printf("STAT: Peers: %u/%u, UDP Que: %u/%u, Threads: %u/%u, Errors: %'llu\n", countLivingPeers(), num_peers, gQueSize(), MAX_TRANS_QUEUE, threads, max_replay_threads, err);
        tt = time(0);
        sleep(180);
    }
    
    //Daemon
    return 0;
}

