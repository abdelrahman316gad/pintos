#include <stddef.h>
#include <stdio.h> 
#define FIXED_POINT_PLACE 14


struct fixed_point
{
    int num ;
};

void init_fixed_point(struct fixed_point* a, int num);


int add(int a,int b);
int sub(int a,int b);

int multiple(int a,int b);

int divide(int a,int b);

int convert_to_int(int a);


