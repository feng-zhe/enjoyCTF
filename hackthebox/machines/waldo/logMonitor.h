#ifndef C_TEMPLATE_H
#define C_TEMPLATE_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <linux/limits.h>
#include <errno.h>
#include <string.h>

#define PROGRAMNAME "logMonitor"

#endif

void printFile(char* filename){
    FILE *fileptr;
    char ch;
    fileptr = fopen(filename, "r");
    if (fileptr == NULL){
        printf("Cannot open file \n");
        exit(0);
    }
    ch = fgetc(fileptr);
    while (ch != EOF){
        printf ("%c", ch);
        ch = fgetc(fileptr);
    }
    fclose(fileptr);
}
