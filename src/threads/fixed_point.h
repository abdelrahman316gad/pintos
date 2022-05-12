#include <stddef.h>
#include <stdio.h> 
#define FIXED_POINT_PLACE 16


struct fixed_point
{
    int num = 0;
};

void init_fixed_point(fixed_point* a, int num);


int add(fixed_point* a, fixed_point *b);
int sub(fixed_point* a, fixed_point *b);

int multiple(fixed_point* a, fixed_point *b);

int divide(fixed_point* a, fixed_point *b);

int convert_to_int(fixed_point* a);


