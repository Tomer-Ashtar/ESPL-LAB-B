#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
typedef struct virus {
unsigned short SigSize;
char virusName[16];
unsigned char* sig;
} virus;

typedef struct link link;
struct link {
link *nextVirus;
virus *vir;
};

struct fun_desc {
char *name;
link* (*fun)(link*,char*);
};
//from prt A

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
    fprintf(output,"Virus name: %s\nVirus size: %d \nsignature: \n",virus->virusName,virus->SigSize);
    PrintHex(output,virus->sig,virus->SigSize);
}
//
int getFileSize(char* filename){
    FILE* fp=fopen(filename,"r");
    fseek(fp, 0, SEEK_END);
    int filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);
    return filesize;
}
void virusFree(virus* vir){
    if(vir!=NULL){
    free(vir->sig);
    }
    free(vir);
}
// Print the data of every link in list to the given stream. Each item followed by a newline character.
void list_print(link *virus_list, FILE* outputfile){
    link* head=virus_list;
    while(head!=NULL){
        printVirus(head->vir,outputfile);
        head=head->nextVirus;
    }

}
link* newLink(virus* data){
    link* newLink = malloc(sizeof(struct link));
    newLink->nextVirus=NULL;
    newLink->vir=data;
    return newLink;
}
/* Add a new link with the given data to the list (at the end CAN ALSO AT BEGINNING), and return a pointer to the list (i.e., the first link in the list). If the 
list is null - create a new entry and return a pointer to the entry. */
link* list_append(link* virus_list, virus* data){
    link* l=newLink(data);
    link* head=virus_list;
    if(virus_list==NULL){
            return l;
    }
    else{
        while(head->nextVirus!=NULL)
        {
             head=head->nextVirus;  
        }
        head->nextVirus=l;
        }
   return virus_list;
   }
link* loadFromFile(FILE* fp,link* list){
    char magic[4];
    fseek(fp, 0, SEEK_END);//gets filesize
    int filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if(fread(&magic,4,sizeof(char),fp)!=0){    
        if(!strcmp(magic,"VISL")==0){//suppose to "virl"
            fprintf(stderr,"file is not acceptable");
                exit(1);
            }
       else {
            int posi=4;
            while(posi<filesize){
                virus* nextVirus=malloc(sizeof(virus));
                nextVirus=readVirus(fp);
                list=list_append(list,nextVirus);
                posi = posi+18+nextVirus->SigSize;
              }
        }
   }
   return list;
}
/* Free the memory allocated by the list. */
void list_free(link *virus_list){
    if(virus_list!=NULL){
        list_free(virus_list->nextVirus);
        virusFree(virus_list->vir);
        free(virus_list);  
    }    
}
link* Loadsignatures(link* list,char* noUse){
    printf("enter signatres' file name\n");
    char buffer[250];
    fgets(buffer,250,stdin);//
    char* filename=NULL;
    sscanf(buffer,"%ms",&filename);
    FILE* fp=fopen(filename,"rb");
    if(fp==NULL)
    {
        fprintf(stderr,"Reading File Error\n");
        exit(1);
    }
    free(filename);
    list= loadFromFile(fp,list);
    fclose(fp);
    return list;
}
link* printSignatures (link* list,char* noUse){
    list_print(list,stdout);
    return list;
}
void detect_virus(char *buffer, unsigned int size, link *virus_list){
    link* head=virus_list;
    while(head!=NULL){
        unsigned char* headsig=head->vir->sig;
        unsigned short sigsize=head->vir->SigSize;
        for(int j=0;j<size-sigsize;j++){///looking for the virus
            if(memcmp(headsig,&buffer[j],(int)sigsize)==0){
                printf("starting position is %d \n",j);
                printf("virus name is: %s\n",head->vir->virusName);
                printf("virus size signature: %d\n\n",sigsize);
                j=size;  
            }
        }
         head=head->nextVirus;
    }
}
link* detectViruses(link* list,char* filename){
    FILE* fp=fopen(filename,"rb");/////
    int filesize=getFileSize(filename);
    char* buffer=malloc(10000);
    unsigned int size;
    if(filesize>10000)
        size=10000;
    else{
        size=filesize;
    }
    if(fread(buffer,size,1,fp)!=0){
        detect_virus(buffer,size,list);
    }
    fclose(fp);
    return list;
}
void neutralize_virus(char *fileName, int signatureOffset){
     FILE* fp=fopen(fileName,"r+");
     if(fp==NULL){
        printf("faild to open the file\n");
        exit(1);
     }
    fseek(fp,signatureOffset,SEEK_SET);
    unsigned char retCommand = 0xC3;
    fwrite(&retCommand,sizeof(retCommand),1,fp);
    fclose(fp);
}
void fixFileEX(char *buffer, unsigned int size, link *virus_list,char* filename){
    link* head=virus_list;
    while(head!=NULL){
        unsigned char* headsig=head->vir->sig;
        unsigned short sigsize=head->vir->SigSize;
        for(int j=0;j<size-sigsize;j++){///looking for the virus
            if(memcmp(headsig,&buffer[j],(int)sigsize)==0){
                neutralize_virus(filename,j);
                //j=size;  
            }
        }
         head=head->nextVirus;
    }
}
link* fixFile(link* list,char* filename){
    FILE* fp=fopen(filename,"r");
    if(fp==NULL){
        printf("faild to open the file\n");
        exit(1);
     }
    int filesize=getFileSize(filename);
    char* buffer=malloc(10000);
    unsigned int size;
    if(filesize>10000)
        size=10000;
    else{
         size=filesize;
        }
    if(fread(buffer,size,1,fp)!=0){
        fixFileEX(buffer,size,list,filename);
        }
        fclose(fp);
        free(buffer);
        return list;
        }


link* quitFile(link* list,char* noUse){
    printf("quit the program goodbye\n");
    list_free(list);
    exit(1);
    return NULL;
}
int main(int argc, char **argv)
{   link* list=NULL;
    char* filename="deafult";
    struct fun_desc menu[] = {
		{"Load signatures", &Loadsignatures},
		{"Print signatures",&printSignatures},
		{"Detect viruses", &detectViruses},
        {"Fix file",&fixFile },
        {"Quit",&quitFile},
		{NULL, NULL}};
        char c[10];
        
        printf("Select operation from the following menu (Cntrl+D to end):\n");
        for(int i=1;i<6;i++)
            printf("%d:%s\n",i,(menu+i-1)->name);

        while(fgets(c,10,stdin)!=NULL){
            int userChoice=atoi(c);
            if(userChoice<1 || userChoice>5){
                printf("not within bounds\n");
                exit(0);
                }
            else{
                printf("within bounds\n");
                if(argc>1)
                    filename=argv[1];
                list=(menu[userChoice-1].fun)(list,filename);
                }
            
            printf("Select operation from the following menu (Cntrl+D to end):\n");
            for(int i=1;i<6;i++)
                printf("%d:%s\n",i,(menu+i-1)->name);   
     }
       return 0;
}