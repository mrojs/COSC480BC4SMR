#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <string.h>

void verifySignature2(BIGNUM * signature, BIGNUM* e, BIGNUM * n , char * hsh, BN_CTX * ctx){

    // get the value of signature to the power e mod n
    BIGNUM *val = BN_new();
    BN_mod_exp ( val , signature , e , n , ctx );

    // the above operation gives a padded value
    // remove padding that starts with "01" and ends with "00"
    // 1. get the number of characters in the padding
    char *padded_val = BN_bn2hex(val);
    int num_zero = 0; // number of zeros in the padding, should be 3
    char c;
    int skips = 0; // number of characters in the padding
    while (num_zero<3){
        c = *(padded_val+skips);
        if (c=='0'){
            num_zero += 1;
        }
        skips++;
    }

    //2. copy the value without the padding
    char *unpadded_val = malloc(sizeof(char)*(strlen(padded_val)-skips));
    strcpy(unpadded_val, padded_val+skips);

    // print the unpadded value
    char *m = "Sig: %s\n";
    printf(m, unpadded_val);
    free(unpadded_val);
}

void printBN (char *msg, BIGNUM *a){
    char *numberstr = BN_bn2hex(a);
    printf("%s %s \n", msg, numberstr);
    OPENSSL_free(numberstr);
}

int main(void)
{
    char *e = "10001"; //obtained from step 2 of task 6 instructions

    // obtained from step 2 of task 6 instructions
    char *n = "F588DFE7628C1E37F83742907F6C87D0FB658225FDE8CB6BA4FF6DE95A23E299F61CE9920399137C090A8AFA42D65E5624AA7A33841FD1E969BBB974EC574C66689377375553FE39104DB734BB5F2577373B1794EA3CE59DD5BCC3B443EB2EA747EFB0441163D8B44185DD413048931BBFB7F6E0450221E0964217CFD92B6556340726040DA8FD7DCA2EEFEA487C374D3F009F83DFEF75842E79575CFC576E1A96FFFC8C9AA699BE25D97F962C06F7112A028080EB63183C504987E58ACA5F192B59968100A0FB51DBCA770B0BC9964FEF7049C75C6D20FD99B4B4E2CA2E77FD2DDC0BB66B130C8C192B179698B9F08BF6A027BBB6E38D518FBDAEC79BB1899D";
    
    // obtained from step 3 of task 6 instructions
    char *signature = "35cd3212f90ca057ec14bf8f10d0d96d79227a9f183e474d5bfc9bc423f513d74ee5239770767ac108a93b528023cdc74583f14bf6dbeaaf4b06f083f09a6d071e55f61a5a0ae5f5a605e8f6a15cfb40df8a94f147d0e4ca246f4b8914b646a9f547d56f2b758930404749c827d93a7ecd013ad65a685b74f6aea0680b5e953547548696fe4461c89c4189f21ecae00d46d89824ea68ac38fcc18f2e518f72c04730e244fa673caad2ba186926c2dc04b61c98fb1d4873ee8ac62be38c838605db61117b5e7676fa1be9e7afb587ac436c402fb44b4a8f7d0d4101cac8d4bfc7ded80de5ccc21614d0779cdde20ef27eb9ec7533829dc921249cb713d34a4907";
    
    //convert the n, e and signature to big number objects
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bige = BN_new();
    BIGNUM *big_n = BN_new();
    BIGNUM *big_signature = BN_new();
    BN_hex2bn(&bige, e);
    BN_hex2bn(&big_n, n);
    BN_hex2bn(&big_signature, signature);
    
    

    char *hsh = "7aff86b0dffe670fde09f3bd30c1defb2fcb5fd06e031d2577078a1e68b88db1"; //obtained by following the steps in the Task 6 instructions
    //function verifySignature2 prints the unpadded signature which can then be passed into the ASN1 decoder
    verifySignature2(big_signature, bige, big_n, hsh, ctx);
    //print the hsh and see if the decoder output matches it
    printf("Hash: %s \n", hsh);
    
}