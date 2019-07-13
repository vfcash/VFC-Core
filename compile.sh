pkill coin
clear
clear
rm coin
rm /usr/bin/coin
gcc -pthread base58.c crc64.c ecc.c sha3.c main.c -lm -o coin
cp coin /usr/bin/coin
chmod 0777 /usr/bin/coin

crontab -l > ncron
echo "@reboot /usr/bin/coin" >> ncron
echo "* * * * * /usr/bin/coin" >> ncron
crontab ncron
rm ncron

echo "Compiled and Installed /usr/bin/coin and /srv/.vfc or ~/.vfc "
