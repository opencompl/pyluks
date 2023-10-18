#!/usr/bin/env sh

dd if=/dev/zero of=luks.cipher_null.img bs=1MiB count=16
dd if=/dev/zero of=luks.default.img bs=1MiB count=16

UUID="abcdabcd-abcd-abcd-abcd-abcdabcdabcd"
echo "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" > masterkey.txt
xxd -r -p masterkey.txt masterkey.bin

sudo /home/grosser/Projects/cryptsetup-2.6.1/cryptsetup luksFormat --type luks1 --key-file passphrase.txt --batch-mode --cipher cipher_null --master-key-file masterkey.bin --uuid "$UUID" --pbkdf-force-iterations 124680 luks.cipher_null.img
sudo /home/grosser/Projects/cryptsetup-2.6.1/cryptsetup luksFormat --type luks1 --key-file passphrase.txt --batch-mode --master-key-file masterkey.bin --uuid "$UUID" --pbkdf-force-iterations 124680 luks.default.img
./pyluks.py pyluks.img


