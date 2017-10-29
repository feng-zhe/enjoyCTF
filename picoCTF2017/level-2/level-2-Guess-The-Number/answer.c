#include <stdio.h>
#include <stdlib.h>

int main(){
    // use readelf -s guess_num, we can find the function 'win' address is 0x0804852b
    // and in function main, our input is divided by 16 (shrl eax,0x4).
    // so we have to know what is 0x804852b0 in a long variable
    long int x = 0x804852b0;
    printf("%d\n",x);
}
