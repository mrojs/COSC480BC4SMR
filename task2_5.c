#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>


BIGNUM *encrypt(BIGNUM *plaintext, BIGNUM *k_public, BIGNUM *n, BN_CTX *ctx)
{
   BIGNUM *res = BN_new();
   BN_mod_exp(res, plaintext, k_public, n, ctx);
   return res; 

}

BIGNUM *decrypt(BIGNUM *ciphertext, BIGNUM *k_private, BIGNUM *n, BN_CTX * ctx)
{
    BIGNUM *res = BN_new();
    BN_mod_exp(res, ciphertext, k_private, n, ctx);
    return res;
}

int verifySignature(BIGNUM * signature, BIGNUM* e, BIGNUM * n , BIGNUM * msg, BN_CTX * ctx){    
    BIGNUM *verif_sig = BN_new();
    BIGNUM *message_mod_n = BN_new();
    BIGNUM *one = BN_new();
    BN_hex2bn(&one , "1");
    BN_mod_exp ( verif_sig , signature , e , n , ctx );
    BN_mod_mul ( message_mod_n, msg , one, n , ctx);

    return(BN_cmp(verif_sig, message_mod_n));
}

BIGNUM *findN(BIGNUM *p, BIGNUM *q, BN_CTX *ctx)
{
    BIGNUM *res = BN_new();
    BN_mul( res, p , q , ctx);
    return res;
}

void printBN (char *msg, BIGNUM *a){
    char *numberstr = BN_bn2hex(a);
    printf("%s %s \n", msg, numberstr);
    OPENSSL_free(numberstr);
}

int main(void)
{
    char *p = "F7E75FDC469067FFDC4E847C51F452DF";
    char *q = "E85CED54AF57E53E092113E62F436F4F";
    char *e = "010001";//"0D88C3";
    char *plaintext = "4120746f702073656372657421";
    char *n = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    
    char *d = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
    char *ciphertext = "6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC";

    char *sig_message = "49206f776520796f752024323030302e";
    char *dif_sig = "49206f776520796f752024333030302e";
    
    char *aliceMsg = "4c61756e63682061206d697373696c652e";
    char *new_n = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";
    char *signature = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
    BN_CTX *ctx = BN_CTX_new();
    //Task 2
    BIGNUM *bigp = BN_new();
    BIGNUM *bigq = BN_new();
    BIGNUM *bige = BN_new();
    BIGNUM *bigPlaintext = BN_new();
    //Task 3 
    BIGNUM *bign = BN_new();
    BIGNUM *bigd = BN_new();
    BIGNUM *bigciphertext = BN_new();
    //Task 4
    BIGNUM *bigSig_message = BN_new();
    BIGNUM *big_dif_sig = BN_new(); 
    //Task 5
    BIGNUM *big_alice_msg = BN_new();
    BIGNUM *big_new_n = BN_new();
    BIGNUM *big_signature = BN_new();

    //Task 2
    BN_hex2bn(&bigp, p);
    BN_hex2bn(&bigq, q);
    BN_hex2bn(&bige, e);
    //Task 3
    BN_hex2bn(&bigPlaintext, plaintext);
    BN_hex2bn(&bign, n);
    BN_hex2bn(&bigd, d);
    //Task 4
    BN_hex2bn(&bigciphertext, ciphertext);
    BN_hex2bn(&bigSig_message, sig_message);
    BN_hex2bn(&big_dif_sig, dif_sig);
    //Task 5
    BN_hex2bn(&big_alice_msg, aliceMsg);
    BN_hex2bn(&big_new_n, new_n);
    BN_hex2bn(&big_signature, signature);
    
    //BIGNUM *n = findN(bigp, bigq, ctx);
    //Task 2
    BIGNUM *encryption = encrypt(bigPlaintext, bige, bign, ctx);
    char *msg = "Encrypted Message: ";
    printBN(msg, encryption);
    //Task 3
    BIGNUM *decryptedHex = decrypt(bigciphertext, bigd, bign, ctx);
    char *msg2 = "Decrypted Hex: ";
    printBN(msg2, decryptedHex);
    //Task 4
    BIGNUM *encryptedSig = encrypt(bigSig_message, bige, bign, ctx);
    char *msg3 = "Digital Signature: ";
    printBN(msg3, encryptedSig);

    BIGNUM *alteredSig = encrypt(big_dif_sig, bige, bign, ctx);
    char *msg4 = "Altered Signature: ";
    printBN(msg4, alteredSig);
    //Task 5
    int alice_sig = verifySignature(big_signature, bige, big_new_n, big_alice_msg, ctx);
    char *msg5 = "Is the signature from Alice? %d ";
    printf(msg5, alice_sig);
    printf("\n");   
    
}