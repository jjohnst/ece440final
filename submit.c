#include "rollcall.h"

int main(int argc, char *argv[]){
    char *mac_addrs[2];
    int count=0;

    //Try to open the file for reading
    FILE *fp=fopen("absences.log","r");
    if(fp==NULL){
        printf("Error. Couldn't open file.\n");
        exit(1);
    }

    //Read entire file
    while(!feof(fp)){

    }
    
    return 0;
}

