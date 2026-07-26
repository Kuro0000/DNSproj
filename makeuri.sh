set -e

ROOT_IP="${1:-172.28.0.10}"
TLD_IP="${2:-172.28.0.11}"
AUTH_IP="${3:-172.28.0.12}"

rm -rf uri
mkdir -p uri

mkdir -p uri/root/com uri/root/test/tld-servers/a
echo "a.tld-servers.test." > uri/root/com/NS    
mkdir -p uri/root/test
echo "a.tld-servers.test." > uri/root/test/NS   
echo "$TLD_IP"             > uri/root/test/tld-servers/a/A  

mkdir -p uri/tld/com/google/ns1 uri/tld/test/shop uri/tld/test/tld-servers/a
echo "ns1.google.com." > uri/tld/com/google/NS  
echo "$AUTH_IP"        > uri/tld/com/google/ns1/A 
echo "$TLD_IP"         > uri/tld/test/tld-servers/a/A

echo "ns2.google.com." > uri/tld/test/shop/NS


mkdir -p uri/auth/com/google/www uri/auth/com/google/mail uri/auth/com/google/ns2 \
         uri/auth/com/google/ns1 uri/auth/test/shop/www
echo "93.184.216.1"  > uri/auth/com/google/A
echo "93.184.216.34" > uri/auth/com/google/www/A
echo "93.184.216.35" > uri/auth/com/google/mail/A
echo "$AUTH_IP"      > uri/auth/com/google/ns1/A
echo "$AUTH_IP"      > uri/auth/com/google/ns2/A
echo "10.10.10.10"   > uri/auth/test/shop/A
echo "10.10.10.11"   > uri/auth/test/shop/www/A

echo "Alberi generati (root=$ROOT_IP tld=$TLD_IP auth=$AUTH_IP):"
find uri -type f | sort | sed 's/^/  /'
