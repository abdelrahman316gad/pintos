#include <stddef.h>
#include <stdio.h> 
#include <fixed_point.h>

void init_fixed_point(struct fixed_point* a, int num){
    a-> num = num << FIXED_POINT_PLACE ;
}

int add(int a, int b){
    return a + b ;
}

int sub(int a, int b){
    return a - b ;
}

int multiple(int a, int b){
    return (a*b) >> FIXED_POINT_PLACE ;
}

int divide(int a, int b){
    return (a / b) << FIXED_POINT_PLACE ;
}

int convert_to_int(int a){
    int draft = a && 1 << FIXED_POINT_PLACE-1 ;
    int res = a>> FILENAME_MAX ;
    return res+ draft ;

}
