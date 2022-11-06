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
    char *m1 = "s1: ";
    printBN(m1,verif_sig);
    char *m2 = "s2: ";
    printBN(m2,message_mod_n);
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
    char *e = "10001";//"65537";
    char *n = "9C1BF1BB2F7F6318155151540F9EC54E4D1058FA309B172990E6330CAC13537C5491B4EAD86E9B896DBB333E8FD20DA6E9F9BAE90D0C1A9EB28EC9702EEF1E057D95EB2D8DA2A94DB39CE7F31936BBA7F17CE6081E6127447A96F4A834DBE242C8A5DB37D5B5E7E442723FB413CF8B0724451E8C918346B909A6FC18A30602EC348D32669527EAE197E8DB35A32B56EB57E8F01059DF6D700C666AD064E5A8A39831AD1D62D5FA92E39A43CD2D35FBD99E335B457DC486282C6612C8DB0F19300D3FE9F0EA4A5E4007C7F6207A537881647A7E456A166FF49358C962FB29277DA17F21CEE74F47D68A56E0E366F8ECDD89DC268C19683B8D8BE2FB47230B7F37";
    char *signature = "2d110638d6dbd75868afaa3867178de213d7a31424d90613ebeb912fdf4f672dc8d314d75665529e6e1f98088e9a481bc18b599aa3579bdb86f85940fc19b075112ac21236ba8e728a064e27b78d5814d16fb4f968fc98dda49c254036debd17662b037f7881b180749e5f3ab4262f6a488436348ea728ef87f361e7db67f552dbd7d1e63071bb8ba3d4ffb964899e9b819b8f57b8644cd506198ee791857c18d189d8f6ea1d681411d9ee17831f5063cf0ef6862a6ee3b1a4c9faf6344c772a808630b0a3dc1b71ec04a7e498bc16853e8426b3c0e535557e7998a3d4d48db6e742e8442012375f09c9fb03e4f5657496edcab9b3f609ff4ca6d15d3afcd14daae49872be384b7f894e268fd4ccbe560971034a6ca3e23586dd1ed9f13103f7134d0b11813179cc7ad7bedcfbf3761b2cbdb3910f0059072a2043dc4bd8b519148fe27a8429d1433f2fccdf3f9dbbbd68c4cee0cde71c31327862faf093a21ec9d79f68e5a876f663fe6899efba36d712719a9eb3711f3bbe00639e3d5f21c2b1861bb84e21c3c343092e630ccdff14f6f622e9fdca9ff59844b6419c41c208987ddba09f227ec0a749bbb4181f4bd3a62a87b95ccaf2834c4003b2521a79210837184ed98d5f99c6055ff16aaeba755a78473a3a655ee5c4d0e3dad2eb5a282db9029960a26f3c2f667c98459cc9fa01ef328e7c3ef9f4037b24a656098c24";
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bige = BN_new();
    BIGNUM *big_new_n = BN_new();
    BIGNUM *big_signature = BN_new();
    BN_hex2bn(&bige, e);
    BN_hex2bn(&big_new_n, n);
    BN_hex2bn(&big_signature, signature);
    
    

    char *msg = "59629d8a4d8fbe8bd05ec5ed65dcff5fc608ff1a816b02f79b73a3b9e9d0f788";
    BIGNUM *msgg = BN_new();
    BN_hex2bn(&msgg, msg);
    //Task 6
    int sig = verifySignature(big_signature, bige, big_new_n, msgg, ctx);
    char *msg5 = "Is the signature correct? %d ";
    printf(msg5, sig);
    printf("\n"); 
    
}