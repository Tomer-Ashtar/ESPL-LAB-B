#include <stdio.h>
#include <stdlib.h>
#include<string.h>
typedef struct virus {
unsigned short SigSize;
char virusName[16];
unsigned char* sig;
} virus;
void PrintHex(FILE* output, unsigned char* buffer,unsigned short length) {
    for (int i=0; i<length; i++)
        fprintf(output,"%02hhX ", buffer[i]);
    fprintf(output,"\n\n");
}
virus* readVirus(FILE* file){
       virus* virus = malloc(sizeof(struct virus));
       int succ=fread(virus,1,18,file);
       if(succ!=0){
              virus->sig=malloc(virus->SigSize);
              fread(virus->sig,1,virus->SigSize,file);
       }
  return virus;
}
void printVirus(virus* virus, FILE* output){
fprintf(output,"virus sigSize : %d \nvirus  name  %s:\nvirus sig : ",virus->SigSize,virus->virusName);
PrintHex(output,virus->sig,virus->SigSize);
}

int main(int argc, char **argv)
{
       char magic[4];
       FILE* fp;
       fp =fopen("signatures-L","r");
        fseek(fp, 0, SEEK_END);//gets filesize
       int filesize = ftell(fp);
       fseek(fp, 0, SEEK_SET);
       if(fread(&magic,4,sizeof(char),fp)!=0){
             if(strcmp(magic,"VIRL")==0){
                     fprintf(stderr,"file is not acceptable");
                     exit(1);
             }
             else {
              int posi=4;
              while(posi<filesize){
                     virus* nextVirus = readVirus(fp);
                     printVirus(nextVirus,stdout);
                     posi = posi+18+nextVirus->SigSize;
                     free(nextVirus);
              }
        }
              
       return 1;
}}