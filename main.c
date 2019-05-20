/*
    VF Cash has been created by James William Fletcher
    http://github.com/mrbid

    A DAG Cryptocurrency for Linux written in C.
    https://vf.cash
    https://vfcash.uk

    Project start date: 23rd of April (2019)
    Project updated:    20th of May   (2019)

    CRYPTO:
    - https://github.com/brainhub/SHA3IUF   [SHA3]
    - https://github.com/esxgx/easy-ecc     [ECDSA]

    Additional Dependencies:
    - CRC64.c - Salvatore Sanfilippo
    - Base58.c - Luke Dashjr

    NOTES:
    Only Supports IPv4 addresses.
    Local storage in /var/log/vfc

    - In it's current state we only track peer's who send a transaction to the server.
    - Entire network is limited to 2,730 transactions per second.

    To use the VFC wallet you need to be running a full node which requires that you
    forward UDP port 58008 on your router to the local machine running the VFC full
    node.

    There is a small transaction Queue and a processing thread to make sure normal
    UDP transmissions do not get particularly blocked up.

    {eers need to be aware of each other by referal, passing the origin ip of a
    transaction across the echo chamber makes this possible, but this also exposes
    the IP address of the clients operating specific transactions. This is fine if
    you are behind a VPN but otherwise, this is generally bad for accountability.
    This could give the an attacker insights that could lead to a successfully
    poisioned block replay. Although the risks are SLIM I would suggest mixing
    this IP list up aka the ip and ipo uint32 arrays when there is more than one
    index using some kind of a random mixing algo.

    Peers can only be part of the network by proving they control VFC currency in a
    given VFC address. This is done by making a transaction from the same IP as the
    node running the full time VFC daemon. Only then will the local VFC daemon
    recieve all transactions broadcast around the VFC p2p network.

    This client will try to broadcast all transactions through the master first
    and then the peer list.

    This is an unordered graph, or using Buzzwords, a 'DAG'. Techincally the whole
    blockchain is not required to operate a full node, just a recent chunk of it.

    Transactions echo two relays deep into the peers, making sure most nodes are
    repeat notified about the transactions due to the echoing of a packet around in
    a two relay deep p2p peers broadcast, making a less reliable UDP protocol
    more reliable and ensuring all peers get the transaction.

    :: Note on block replays
    I had a bit of a problem where any node could bypass the transaction limiter by
    exploiting the use of block replays, or trick individual clients into thinking
    a transactions has taken place while the rest of the network remains oblivious.
    My solution to this problem is to only allow replays from one other IP that is
    not the master at any one time. Every time a replay takes place this IP will
    change to another random peer in the local peer list. Now this means only one
    node can ever bypass the limiter and that is the randomly selected node by the
    local client.

    It is possible that a malicious user could monitor traffic on the network, identifying
    the addresses used by your nodes IP address and then by chance if you ever request a
    block replay from them they could poision your blockchain. Also, a user could make
    a program to archive the addresses used by each node IP until one of the requests
    a replay from them (eventually) and directly poision their blockchain. There are
    no obvious benefits from doing this, if they did do this it would be obvious, a bit
    annoying, and require an enire replay. For example they could pretend your balance
    had been depleted or increased to an obscene amount, but that's about it.
    In which case you'd just assume the obvious, that your blockchain replay was corrupt
    which it was (albeit maliciously), and you'd resync. (hopefully)

    Block Replays happen in reverse to make sure the latest transactions arrive first.
    Block Replays are capped to 618kb a second to increase UDP reliability

    Scalability:
    At the moment it would seem that for every 5mb of blockchain that a transaction
    takes ~20ms to process. That means with 1gb of blockchain it would take ~4 seconds
    for one node to process one transaction. 13 minutes with 200gb size blockchain.
    But it's a DAG thus you don't need the full block chain to process transactions !
    So .. 20ms or less most of the time if you are that way inclined ! :-)

    Distributed under the MIT software license, see the accompanying
    file COPYING or http://www.opensource.org/licenses/mit-license.php.

*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h> //mkdir
#include <time.h> //time()
#include <unistd.h> //sleep
#include <locale.h> //setlocale
#include <signal.h> //SIGPIPE
#include <pthread.h> //Threading

#include "ecc.h"
#include "sha3.h"
#include "crc64.h"
#include "base58.h"

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////

#define ERROR_MAXCHAINHR -1
#define ERROR_LIMITED -2
#define ERROR_NOFUNDS -3
#define ERROR_SIGFAIL -4
#define ERROR_AMOUNT -5
#define ERROR_UIDEXIST -6

#define MAX_TRANS_QUEUE 512
#define MAX_THREADS 128
#define MAX_PEERS 8192
#define MAX_TRANS_PER_TSEC 8192 //must be divisable by 2 [this is actually transactions per MAX_SECONDS_PER_TRANS seconds.]
#define MAX_SECONDS_PER_TRANS 3 //3 sec

#define MAX_TRANS_PER_TSEC_MEM MAX_TRANS_PER_TSEC*2
#define RECV_BUFF_SIZE 1024
#define MIN_LEN 256
#define MAX_LEN 1024

#define CHAIN_FILE "/var/log/vfc/blocks.dat"

#define uint unsigned int
#define ulong unsigned long long int
#define mval uint32_t

//Make sure everyone on same level chain
ulong err = 0;
const char version[]="0.18";
const uint16_t gport = 58008;
const char master_ip[] = "68.183.49.225"; //1152856545 / 0x44B731E1;
uint32_t replay_allow = 0;
uint threads = 0;

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

void toHex(char* out, const uint8_t* in, const uint len)
{
    for(uint i = 0; i < len; i++)
    {
        char hb[4];
        sprintf(hb, "%02x", in[i]);
        strcat(out, hb);
    }
}

void fromHex(unsigned char* out, const char* in, const uint len)
{
    for(uint i = 0; i < len; i++)
        sscanf(in + (i*2), "%2hhx", &out[i]);
}

char* getHome()
{
    char *ret;
    if((ret = getenv("HOME")) == NULL)
        ret = getpwuid(getuid())->pw_dir;
    return ret;
}

void dump(const char* file, const void* dat, const uint len)
{
    FILE* f = fopen(file, "w");
    if(f)
    {
        fwrite(dat, len, 1, f);
        fclose(f);
    }
}

uint qRand(const uint min, const uint max)
{
    static time_t ls = 0;
    if(time(0) > ls)
    {
        srand(time(0));
        ls = time(0) + 33;
    }
    return ((rand() / RAND_MAX) * (max-min))+min; //(rand()%(max-min))+min;
}

void timestamp()
{
    time_t ltime = time(0);
    printf("\n\033[1m\x1B[31m%s\x1B[0m\033[0m", asctime(localtime(&ltime)));
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
    sha3_Init384(&c);
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

uint32_t peers[MAX_PEERS];
time_t peer_timeouts[MAX_PEERS];
uint num_peers = 0;

int csend(const uint32_t ip, const char* send, const size_t len)
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

int verifyChain(const char* path)
{
    //Genesis Public Key
    uint8_t gpub[ECC_CURVE+1];
    fromHex(gpub, "03a1cc42d4c82b2b0af383690a329dd8456adf29b6b9ed5ea4569e36aa1a87089f9d92f360503cbc15a431e2614b84b3af", ECC_CURVE+1);

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
        printf("Look's like the blocks.dat cannot be found please make sure you chmod 0777 /var/log/vfc\n");
        return 0;
    }
    

    //Look's legit
    return 1;
}

int isMasterNode(const uint32_t ip)
{
    if(ip == peers[0])
        return 1;
    return 0;
}

void setMasterNode()
{
    memset(peers, 0, sizeof(uint32_t)*MAX_PEERS);
    memset(peer_timeouts, 0, sizeof(uint32_t)*MAX_PEERS);
    struct in_addr a;
    inet_aton(master_ip, &a);
    peers[0] = a.s_addr;
    num_peers = 1;
}

void peersBroadcast(const char* dat, const size_t len)
{
    for(uint i = 1; i < num_peers; ++i) //Start from 1, skip master
        csend(peers[i], dat, len);
}

void resyncBlocks()
{
    //Resync from Master
    csend(peers[0], "r", 1);

    //Also Resync from a Random Node (Resync is called fairly often so eventually the random distribution across nodes will fair well)
    if(num_peers > 2)
        replay_allow = peers[qRand(1, num_peers)];
    else if(num_peers == 2)
        replay_allow = peers[1];

    //Alright ask this peer to replay to us too
    csend(replay_allow, "r", 1);    
}

int sendMaster(const char* dat, const size_t len)
{
    return csend(peers[0], dat, len);
}

int isPeer(const uint32_t ip)
{
    for(uint i = 0; i < num_peers; ++i)
        if(peers[i] == ip)
            return 1;
    return 0;
}

//Peers are only replaced if they have not responded in a week, otherwise we still consider them contactable until replaced.
void addPeer(const uint32_t ip)
{
    //Never add local host
    if(ip == 0x7F000001)
        return;

    //Is already in peers?
    uint freeindex = 0;
    for(uint i = 0; i < num_peers; ++i)
    {
        if(peers[i] == ip)
        {
            peer_timeouts[i] = time(0) + 604800; //Renew 1 week expirary
            return;
        }

        if(freeindex == 0 && i != 0 && peer_timeouts[i] < time(0)) //0 = Master, never a free slot.
            freeindex = i;
    }

    //Try to add to existing free slot first, if not continue sequential array, if possible.
    if(freeindex != 0)
    {
        peers[freeindex] = ip;
        peer_timeouts[freeindex] = time(0) + 604800; //1 week expire
    }
    else if(num_peers < MAX_PEERS-1)
    {
        peers[num_peers] = ip;
        peer_timeouts[num_peers] = time(0) + 604800; //1 week expire
        num_peers++;
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
/* ~ Rate Limiting
*/

struct lim
{
    time_t ts;
    addr ad;
};
struct lim lim[MAX_TRANS_PER_TSEC_MEM];

//Are there atleast two limit slots available for this transaction?
int islimslot()
{
    int c = 0;
    for(uint i = 0; i < MAX_TRANS_PER_TSEC_MEM; i++)
    {
        if(time(0) > lim[i].ts || lim[i].ts == 0)
        {
            c++;
            if(c == 2)
                return 1;
        }
    }
    return 0;
}

//Ok add this transaction to the two available limit slots
void add_lim(addr* from, addr* to)
{
    int c = 0;
    for(uint i = 0; i < MAX_TRANS_PER_TSEC_MEM; i++)
    {
        if(time(0) > lim[i].ts || lim[i].ts == 0)
        {
            if(c == 0)
            {
                lim[i].ts = time(0)+MAX_SECONDS_PER_TRANS;
                memcpy(&lim[i].ad, from->key, ECC_CURVE+1);
                c = 1;
                continue;
            }

            if(c == 1)
            {
                lim[i].ts = time(0)+MAX_SECONDS_PER_TRANS;
                memcpy(&lim[i].ad, to->key, ECC_CURVE+1);
                return;
            }
        }
    }
}

//Check if either addresses are limited, if so, no transaction
int islim(addr* from, addr* to)
{
    for(uint i = 0; i < MAX_TRANS_PER_TSEC_MEM; i++)
        if(lim[i].ts != 0 && time(0) < lim[i].ts)
            if(memcmp(&lim[i].ad, from->key, ECC_CURVE+1) == 0 || memcmp(&lim[i].ad, to->key, ECC_CURVE+1) == 0)
                return 1;

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

*/

//The Variables that make up `the Queue`
struct trans tq[MAX_TRANS_QUEUE];
uint32_t ip[MAX_TRANS_QUEUE];
uint32_t ipo[MAX_TRANS_QUEUE];
unsigned char limit[MAX_TRANS_QUEUE];

//Add a transaction to the Queue
void aQue(struct trans *t, const uint32_t iip, const uint32_t iipo, const unsigned char il)
{
    //if duplicate transaction bail
    int freeindex = -1;
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].uid == t->uid)
            return;
        
        if(freeindex == -1 && tq[i].amount == 0)
            freeindex = i;
    }

    //if fresh transaction add at available slot
    if(freeindex != -1)
    {
        memcpy(&tq[freeindex], t, sizeof(struct trans));
        ip[freeindex] = iip;
        ipo[freeindex] = iipo;
        limit[freeindex] = il;
    }
}

//pop the first living transaction index off the Queue
int gQue()
{
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
        if(tq[i].amount != 0)
            return i;
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

//Replay blocks to x address (in reverse, latest first to oldest last)
void replayBlocks(const uint32_t ip)
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = len - sizeof(struct trans); i > 0; i -= sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                //Generate Packet (pc)
                const size_t len = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE; //lol this is always sizeof(struct trans)+1 im silly but i've done it now so..
                char pc[MAX_LEN];
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
                usleep(333); //3k, 211 byte packets / 618kb a second
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}
void *replayBlocksThread(void *arg)
{
    nice(19); //Very low priority thread
    const uint32_t *ip = arg;
    replayBlocks(*ip);
}

//print received transactions
void printIns(addr* a)
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.to.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.from.key, ECC_CURVE+1);
                    printf("%s > %u\n", pub, t.amount);
                }
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
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
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.from.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.to.key, ECC_CURVE+1);
                    printf("%s > %u\n", pub, t.amount);
                }
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}

//get balance
mval getBalance(addr* from)
{
    mval rv = 0;
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return 0;
            }
            
        }

        fclose(f);
    }
    return rv;
}

//Calculate if an address has the value required to make a transaction of x amount.
int hasbalance(const uint64_t uid, addr* from, mval amount)
{
    mval rv = 0;
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(t.uid == uid)
                {
                    fclose(f);
                    return ERROR_UIDEXIST;
                }

                if(memcmp(&t.to, from, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from, from, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return 0;
            }
            
        }

        fclose(f);
    }
    if(rv >= amount)
        return 1;
    else
        return 0;
}

//Execute Transaction
int process_trans(const uint64_t uid, addr* from, addr* to, mval amount, sig* owner, const uint limon)
{
    //Is the amount 0?
    if(amount <= 0)
        return ERROR_AMOUNT;

    //We reached max hour trans?
    if(limon == 1)
        if(islimslot() == 0)
            return ERROR_MAXCHAINHR;

    //Make sure addresses aint limited
    if(limon == 1)
        if(islim(from, to) == 1)
            return ERROR_LIMITED;
    
    //Check this address has the required value for the transaction (and that UID is actually unique)
    const int hbr = hasbalance(uid, from, amount);
    if(hbr == 0)
        return ERROR_NOFUNDS;
    else if(hbr < 0)
        return hbr;

    //Ok let's register the transaction
    FILE* f = fopen(CHAIN_FILE, "a");
    if(f)
    {
        //Create new memory trans for chain
        struct trans t;
        memset(&t, 0, sizeof(struct trans));
        t.uid = uid;
        memcpy(t.from.key, from->key, ECC_CURVE+1);
        memcpy(t.to.key, to->key, ECC_CURVE+1);
        t.amount = amount;
        
        //Verify
        uint8_t thash[ECC_CURVE];
        makHash(thash, &t);
        if(ecdsa_verify(from->key, thash, owner->key) == 0)
            return ERROR_SIGFAIL;

        //Add the sig now
        memcpy(t.owner.key, owner->key, ECC_CURVE*2);
        
        //Write to chain
        fwrite(&t, sizeof(struct trans), 1, f);
        fclose(f);

        //Memory limit
        add_lim(from, to);
    }

    //Success
    return 1;
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
    fromHex(gpub, "03a1cc42d4c82b2b0af383690a329dd8456adf29b6b9ed5ea4569e36aa1a87089f9d92f360503cbc15a431e2614b84b3af", ECC_CURVE+1);

    //Make Genesis Block (does not need to be signed or have src addr, or have a UID)
    struct trans t;
    memset(&t, 0, sizeof(struct trans));
    t.amount = 0xFFFFFFFF;
    memcpy(&t.to.key, gpub, ECC_CURVE+1);
    FILE* f = fopen(CHAIN_FILE, "w");
    if(f)
    {
        fwrite(&t, sizeof(struct trans), 1, f);
        fclose(f);
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
/* ~ Console & Socket I/O
*/

void savemem()
{
    FILE* f = fopen("/var/log/vfc/peers.mem", "w");
    if(f)
    {
        fwrite(peers, sizeof(uint32_t), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen("/var/log/vfc/lim.mem", "w");
    if(f)
    {
        fwrite(lim, sizeof(struct lim), MAX_TRANS_PER_TSEC_MEM, f);
        fclose(f);
    }
}

void loadmem()
{
    FILE* f = fopen("/var/log/vfc/peers.mem", "r");
    if(f)
    {
        if(fread(peers, sizeof(uint32_t), MAX_PEERS, f) != MAX_PEERS)
            printf("\033[1m\x1B[31mPeers Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
        fclose(f);
    }
    f = fopen("/var/log/vfc/lim.mem", "r");
    if(f)
    {
        if(fread(lim, sizeof(struct lim), MAX_TRANS_PER_TSEC_MEM, f) != MAX_TRANS_PER_TSEC_MEM)
            printf("\033[1m\x1B[31mLimiter Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
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

int isNodeRunning()
{
    struct sockaddr_in server;

    //Create socket
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
    while(1)
    {
        //See if there is a new transaction to process
        const int i = gQue();
        if(i == -1)
        {
            usleep(333); //Little delay if queue is empty we dont want to thrash cycles
            continue;
        }  
        
        //Process the transaction
        const int r = process_trans(tq[i].uid, &tq[i].from, &tq[i].to, tq[i].amount, &tq[i].owner, limit[i]);

        //Good transaction!
        if(r == 1 && limit[i] == 1)
        {
            //Dead Transaction (do not repeat)
            if(ipo[i] != 0)
            {
                addPeer(ipo[i]); //Track this client by attached origin
                addPeer(ip[i]); //Track this client by origin
            }
            else //Broadcast but prevent clients repeating message
            {
                //Track this client from origin
                addPeer(ip[i]);

                //Construct a non-repeatable transaction and tell our peers
                const uint32_t origin = ip[i];
                const size_t len = 1+sizeof(uint64_t)+sizeof(uint32_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE; //Again it's basically sizeof(struct trans)+uint64_t+1
                char pc[MAX_LEN];
                pc[0] = 'd';
                char* ofs = pc + 1;
                memcpy(ofs, &origin, sizeof(uint32_t));
                ofs += sizeof(uint32_t);
                memcpy(ofs, &tq[i].uid, sizeof(uint64_t));
                ofs += sizeof(uint64_t);
                memcpy(ofs, tq[i].from.key, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(ofs, tq[i].to.key, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(ofs, &tq[i].amount, sizeof(mval));
                ofs += sizeof(mval);
                memcpy(ofs, tq[i].owner.key, ECC_CURVE*2);
                peersBroadcast(pc, len);
            }
        }

        //Alright this transaction is PROCESSED
        tq[i].amount = 0; //Signifies transaction as invalid / completed / processed (basically done)
    }
}

int main(int argc , char *argv[])
{
    //Suppress Sigpipe
    signal(SIGPIPE, SIG_IGN);

    //Hijack CTRL+C
    signal(SIGINT, sigintHandler);

    //create vfc dir
    mkdir("/var/log/vfc", 0777);

    //Outgoings and Incomings
    if(argc == 3)
    {
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
            printf("\n\x1B[33mTo get an address balance use:\x1B[0m\n ./coin <address public key>\n\n");
            printf("\x1B[33mTo check sent transactions from an address use:\x1B[0m\n ./coin out <address public key>\n\n");
            printf("\x1B[33mTo check received transactions from an address use:\x1B[0m\n ./coin in <address public key>\n\n");
            printf("\x1B[33mTo make a transaction use:\x1B[0m\n ./coin <sender public key> <reciever public key> <amount> <sender private key>\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain resync use:\x1B[0m\n ./coin resync\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain sync use:\x1B[0m\n ./coin sync\x1B[0m\n\n");
            printf("\x1B[33mTo create a new Address, Public / Private Key-Pair:\x1B[0m\n ./coin new\x1B[0m\n\n");
            printf("\x1B[33mTo get started running a dedicated node, execute ./coin on a seperate screen, you will need to make atleast one transaction a month to be indexed by the network.\x1B[0m\n\n");
            exit(0);
        }

        //sync
        if(strcmp(argv[1], "sync") == 0)
        {
            setMasterNode();
            resyncBlocks();
            
            time_t ct = time(0)+33;
            __off_t ls = 0;
            while(1)
            {
                printf("\033[H\033[J");
                struct stat st;
                stat(CHAIN_FILE, &st);
                if(st.st_size != ls)
                {
                    ls = st.st_size;
                    ct = time(0)+33;
                }
                printf("\x1B[33m%.1f\x1B[0m kb downloaded press CTRL+C to Quit.\n", (double)st.st_size / 1000);
                if(time(0) > ct)
                    break;
                sleep(1);
            }
            printf("\x1B[33mLooks like you have the entire chain now.\x1B[0m\n");
            exit(0);
        }

        //resync
        if(strcmp(argv[1], "resync") == 0)
        {
            makGenesis(); //Erases chain and resets it for a full resync
            setMasterNode();
            resyncBlocks();
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
    }

    //Let's make sure we're booting with the right damn chain
    if(verifyChain(CHAIN_FILE) == 0)
    {
        printf("\033[1m\x1B[31mSorry you're not on the right chain. Please resync by running ./sync resync\x1B[0m\033[0m\n\n");
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

        struct timespec s;
        clock_gettime(CLOCK_REALTIME, &s);
        const mval bal = getBalance(&from);
        struct timespec e;
        clock_gettime(CLOCK_REALTIME, &e);
        long int td = (e.tv_nsec - s.tv_nsec);
        if(td > 0){td /= 1000000;}
        else if(td < 0){td = 0;}
        
        setlocale(LC_NUMERIC, "");
        printf("\x1B[33mThe Balance for Address '%s' is %'u VFC. Time Taken %li Milliseconds.\x1B[0m\n\n", argv[1], bal, td);
        exit(0);
    }

    //Does user just wish to execute transaction?
    if(argc > 1)
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
        
        //Construct Transaction
        struct trans t;
        memset(&t, 0, sizeof(struct trans));
        //
        memcpy(t.from.key, from, ECC_CURVE+1);
        memcpy(t.to.key, to, ECC_CURVE+1);
        t.amount = atoi(argv[3]);

        //Too low amount?
        if(t.amount <= 0)
        {
            printf("\033[1m\x1B[31mSorry the amount you provided was too low, please try 1 VFC or above.\x1B[0m\033[0m\n\n");
            exit(0);
        }

    //Get balance..
    setlocale(LC_NUMERIC, "");
    printf("\n\x1B[33mBefore Balance:\x1B[0m\n");
    printf("'%s' :: \x1B[33m%'u VFC.\x1B[0m\n\n", argv[1], getBalance(&t.from));
    printf("'%s' :: \x1B[33m%'u VFC.\x1B[0m\n", argv[2], getBalance(&t.to));

        //UID Based on timestamp & signature
        time_t ltime = time(NULL);
        char suid[MIN_LEN];
        sprintf(suid, "%s/%s", asctime(localtime(&ltime)), argv[1]); //timestamp + base58 from public key
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
        const uint32_t origin = 0;
        const size_t len = 1+sizeof(uint64_t)+sizeof(uint32_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE; //Again it's basically sizeof(struct trans)+uint64_t+1
        char pc[MAX_LEN];
        pc[0] = 't';
        char* ofs = pc + 1;
        memcpy(ofs, &origin, sizeof(uint32_t));
        ofs += sizeof(uint32_t);
        memcpy(ofs, &t.uid, sizeof(uint64_t));
        ofs += sizeof(uint64_t);
        memcpy(ofs, from, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, to, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, &t.amount, sizeof(mval));
        ofs += sizeof(mval);
        memcpy(ofs, t.owner.key, ECC_CURVE*2);

        //Send to local host so that our local daemon broadcasts it.
        sendMaster(pc, len);
        peersBroadcast(pc, len);

        //Log
        char howner[MIN_LEN];
        memset(howner, 0, sizeof(howner));
        size_t zlen = MIN_LEN;
        b58enc(howner, &zlen, t.owner.key, ECC_CURVE);

        printf("\n\x1B[33mPacket Size: %lu. %u VFC. Sending Transaction...\x1B[0m\n", len, t.amount);
        printf("\033[1m\x1B[31m%s > %s : %u : %s\x1B[0m\033[0m\n", argv[1], argv[2], t.amount, howner);
        printf("\x1B[33mTransaction Sent.\x1B[0m\n\n");

    //Get balance again..
    sleep(6);
    setlocale(LC_NUMERIC, "");
    printf("\x1B[33mAfter Balance:\x1B[0m\n");
    printf("'%s' :: \x1B[33m%'u VFC.\x1B[0m\n\n", argv[1], getBalance(&t.from));
    printf("'%s' :: \x1B[33m%'u VFC.\x1B[0m\n\n", argv[2], getBalance(&t.to));

        //Done
        exit(0);
    }
    
    //Launch Info
    timestamp();
    printf("\n\x1B[33mVFC - Virtual Finance Coin\n");
    printf("https://github.com/mrbid\n");
    printf("v%s\x1B[0m\n\n", version);
    printf("\x1B[33mYou will have to make a transaction before your IPv4 address registers\nwith the mainnet when running a full time node/daemon.\x1B[0m\n\n");
    printf("\x1B[33mTo get a full command list use:\x1B[0m\n ./coin help\n\n");

    //Launch the Transaction Processing thread
    pthread_t tid;
    pthread_create(&tid, NULL, processThread, NULL);
	
    //Resync Blocks
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
        while(1)
        {
            //Client Command
            memset(rb, 0, sizeof(rb));
            read_size = recvfrom(s, rb, RECV_BUFF_SIZE-1, 0, (struct sockaddr *)&client, &slen);

            //Are we the same node sending to itself, if so, ignore.
            if(server.sin_addr.s_addr == client.sin_addr.s_addr) //I know, this is very rarily ever effective. If ever.
                continue;

            //Is this a [fresh trans / dead trans] ?
            if(rb[0] == 't' || rb[0] == 'd')
            {
                //Root origin peer address
                uint32_t origin = 0;

                //Decode packet into a Transaction & Origin
                struct trans t;
                memset(&t, 0, sizeof(struct trans));
                char* ofs = rb+1;
                memcpy(&origin, ofs, sizeof(uint32_t)); //grab root origin address
                ofs += sizeof(uint32_t);
                memcpy(&t.uid, ofs, sizeof(uint64_t)); //grab uid
                ofs += sizeof(uint64_t);
                memcpy(t.from.key, ofs, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(t.to.key, ofs, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(&t.amount, ofs, sizeof(mval));
                ofs += sizeof(mval);
                memcpy(t.owner.key, ofs, ECC_CURVE*2);

                //Process Transaction
                aQue(&t, client.sin_addr.s_addr, origin, 1); //Threaded (using processThread()) not to jam up UDP relay
                
                //Increment Requests
                reqs++;
            }

            //Request to replay all my blocks?
            else if(rb[0] == 'r')
            {
                //Is this peer even registered? if not, suspect foul play, not part of verified network.
                if(isPeer(client.sin_addr.s_addr) == 1)
                {
                    //Max threads limit; reset every x time period
                    if(threads < MAX_THREADS)
                    {
                        pthread_t tid;
                        pthread_create(&tid, NULL, replayBlocksThread, &client.sin_addr.s_addr); //Threaded not to jam up UDP relay
                        threads++;
                    }

                    //Increment Requests
                    reqs++;
                }
            }

            //Is this a replay block?
            else if(rb[0] == 'p')
            {
                //This replay has to be from the specific trusted node, or the master. If it's a trusted node, we know it's also a peer so. All good.
                if(client.sin_addr.s_addr == replay_allow || isMasterNode(client.sin_addr.s_addr) == 1)
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
                    
                    //Increment Requests
                    reqs++;
                }
            }

            //Log Requests per Second
            if(st < time(0))
            {
                //Log Metrics
                printf("\x1B[33mSTATS: Req/s: %ld, Peers: %u, Errors: %llu\x1B[0m\n", reqs / (time(0)-tt), num_peers, err);

                //do some utilities
                savemem(); //Save memory state

                //Reset thread count / limit
                threads = 0;

                //Let's execute a resync every 3*60 mins (3hr)
                if(rsi >= 60)
                {
                    rsi = 0;
                    resyncBlocks();
                }

                //Prep next loop time
                rsi++;
                tt = time(0);
                reqs = 0;
                st = time(0)+180; //Every 3 mins
            }
        }
    }
    
    //Daemon
    return 0;
}


