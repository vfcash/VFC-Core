clear
clear
pkill coin
pkill vfc
rm coin
rm vfc
rm /usr/bin/coin
rm /usr/bin/vfc
gcc -pthread base58.c crc64.c ecc.c sha3.c main.c -lm -o coin
cp vfc /usr/bin/vfc
chmod 0777 /usr/bin/vfc

crontab -l > ncron
echo "* * * * * /usr/bin/coin" >> ncron
crontab ncron
rm ncron

echo "Compiled and Installed /usr/bin/coin and /srv/.vfc or ~/.vfc "
