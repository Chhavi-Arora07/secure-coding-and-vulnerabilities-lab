#include <stdio.h>
int main(void){
    int x = 0;             /* initialised before use */
    if (x > 10) 
        printf("x is greater than 10\n");
    else
        printf("x is not greater than 10\n");
    return 0;
}