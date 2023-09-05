#!/usr/bin/env sh

dd if=/dev/zero of=test.img bs=1MiB count=16

echo "222c7552fa1c58072585ca625befcabb530606336dc9407550a43e98d503d58f2320b86f7ee47d1f7479e64a457e14985dd33d3b053e32e0c8443b385cd18628" > masterkey.txt
echo "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" > masterkey.txt
xxd -r -p masterkey.txt masterkey.bin

#sudo cryptsetup luksFormat --type luks1 --key-file passphrase.txt --batch-mode --cipher cipher_null --master-key-file masterkey.bin test.img
sudo cryptsetup luksFormat --type luks1 --key-file passphrase.txt --batch-mode --master-key-file masterkey.bin test.img

