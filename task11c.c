#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>



BIGNUM *privkey(BIGNUM *p, BIGNUM *q, BIGNUM *e, BN_CTX *ctx){
    BIGNUM *n = BN_new();
    BN_mul(n , p , q , ctx);
    
    BIGNUM *phi = BN_new();
    BIGNUM *one = BN_new();
    BN_hex2bn(&one , "1");
    BIGNUM *res1 = BN_new();
    BIGNUM *res2 = BN_new();
    BN_sub(res1, p, one);
    BN_sub(res2, q, one);
    BN_mul(phi , res1, res2, ctx);
    BIGNUM *d = BN_new();
    BN_mod_inverse( d , phi, n , ctx);
    return d;
}

void printBN (char *msg, BIGNUM *a){
    char *numberstr = BN_bn2dec(a);
    printf("%s %s \n", msg, numberstr);
    OPENSSL_free(numberstr);
}

int main(void){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BN_hex2bn(&p , "F7E75FDC469067FFDC4E847C51F452DF");
    BIGNUM *q = BN_new();
    BN_hex2bn(&q , "E85CED54AF57E53E092113E62F436F4F");
    BIGNUM *e = BN_new();
    BN_hex2bn(&e , "0D88C3");
    BIGNUM *d = privkey(p,q,e,ctx);
    char *msg = "Private key: ";
    printBN(msg, d);
}
