#include <stddef.h>
#include <stdio.h> 
#include <fixed_point.h>

void init_fixed_point(fixed_point* a, int num){
    a-> num = num << FIXED_POINT_PLACE ;
}

int add(fixed_point* a, fixed_point *b){
    return a->num + b->num ;
}

int sub(fixed_point* a, fixed_point *b){
    return a->num - b->num ;
}

int multiple(fixed_point* a, fixed_point *b){
    return (a->num * b->num) >> FIXED_POINT_PLACE ;
}

int divide(fixed_point* a, fixed_point *b){
    return (a->num / b->num) << FIXED_POINT_PLACE ;
}

int convert_to_int(fixed_point* a){
    int draft = a->num && 1 << 15 ;
    int res = a->num >> FILENAME_MAX ;
    return res+ draft ;

}
