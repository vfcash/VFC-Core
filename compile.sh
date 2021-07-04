clear
clear
apt --assume-yes update && upgrade
apt install --assume-yes crontab
apt install --assume-yes wget
apt install --assume-yes gcc
apt install --assume-yes xterm
apt install --assume-yes qt5-default
apt install --assume-yes libqt5widgets5
apt install --assume-yes libsdl2-2.0-0
apt install --assume-yes libsdl2-net-2.0-0
apt install --assume-yes libomp-9-dev
clear
clear
pkill vfc
rm bin/vfc
rm /usr/bin/vfc
rm /usr/bin/vfui
rm /usr/bin/vfwallet
rm /usr/bin/cminer
gcc -std=gnu99 -Ofast -pthread base58.c crc64.c ecc.c sha3.c main.c -lm -o bin/vfc
cp bin/vfc /usr/bin/vfc
cp bin/vfui /usr/bin/vfui
cp bin/vfwallet /usr/bin/vfwallet
cp bin/cminer /usr/bin/cminer
chmod +x /usr/bin/vfc
chmod +x /usr/bin/vfui
chmod +x /usr/bin/vfwallet
chmod +x /usr/bin/cminer
crontab -l > ncron
if grep -qxF '*/6 * * * * /usr/bin/vfc' ncron; then
    echo "Cron1 Exists";
else
    echo "*/6 * * * * /usr/bin/vfc" >> ncron
    crontab ncron
    echo "Cron1 Added";
fi
rm ncron
clear
clear
echo "Compiled and Installed /usr/bin/vfc and /srv/.vfc or ~/.vfc "
echo "Don't forget to forward UDP port 8787 if behind a router."
echo "For more information type; vfc help or vfui for the GUI"
