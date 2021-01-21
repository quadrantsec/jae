
#define MAX_ITEM_SIZE		128

typedef struct _Simple_Array _Simple_Array;
struct _Simple_Array
{
    char item[MAX_ITEM_SIZE];
};


struct _Simple_Array *Load_Simple_File ( const char *filename );


