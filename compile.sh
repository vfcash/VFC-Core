clear
clear
apt update && upgrade
apt install crontab
apt install gcc
clear
clear
pkill coin
rm coin
rm /usr/bin/coin
pkill vfc
rm vfc
rm /usr/bin/vfc
gcc -pthread base58.c crc64.c ecc.c sha3.c main.c -lm -o vfc
cp vfc /usr/bin/vfc
chmod 0777 /usr/bin/vfc

crontab -l > ncron
if grep -qxF '* * * * * /usr/bin/vfc' ncron; then
    echo "Cron Exists";
else
    echo "* * * * * /usr/bin/vfc" >> ncron
    crontab ncron
    echo "Cron Added";
fi
rm ncron

echo "Compiled and Installed /usr/bin/vfc and /srv/.vfc or ~/.vfc "
echo "vfc help"
echo "Don't forget to forward UDP port 8787 if behind a router."
