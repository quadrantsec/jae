

#define 	BLUEDOT_TYPE_IP		1
#define		BLUEDOT_TYPE_HASH	2

#define		BLUEDOT_ALERT_ALERT	1
#define		BLUEDOT_ALERT_REPORT	2

#define		BLUEDOT_USER_AGENT	"User-Agent: JAE"

#define 	BLUEDOT_IP_LOOKUP_URL 		"&ip="
#define 	BLUEDOT_HASH_LOOKUP_URL 	"&hash="
#define 	BLUEDOT_FILENAME_LOOKUP_URL 	"&filename="
#define 	BLUEDOT_URL_LOOKUP_URL 		"&url="
#define 	BLUEDOT_JA3_LOOKUP_URL 		"&ja3="

#define		BLUEDOT_DEFAULT_MEMORY_SLOTS	5
#define		BLUEDOT_JSON_SIZE		1024

#define		BLUEDOT_API_USER		32
#define		BLUEDOT_CATEGORY		16
#define		BLUEDOT_COMMENTS		1024
#define		BLUEDOT_SOURCE			128
#define		BLUEDOT_CTIME			16
#define		BLUEDOT_MTIME			16
#define		BLUEDOT_QUERY			64
#define		BLUEDOT_LAST_SEEN		16
#define		BLUEDOT_QUERY_TYPE		16


#define		BLUEDOT_CAT_CATEGORY		16
#define		BLUEDOT_CAT_DESCRIPTION		128

typedef struct _Bluedot_Cat_List _Bluedot_Cat_List;
struct _Bluedot_Cat_List
{
    uint8_t     code;
    char        category[BLUEDOT_CAT_CATEGORY];
    char	description[BLUEDOT_CAT_DESCRIPTION];
};

typedef struct _Bluedot_IP_Queue _Bluedot_IP_Queue;
struct _Bluedot_IP_Queue
{
    unsigned char ip[MAX_IP_BIT_SIZE];
};

typedef struct _Bluedot_Hash_Queue _Bluedot_Hash_Queue;
struct _Bluedot_Hash_Queue
{
    char hash[SHA256_HASH_SIZE+1];
};


typedef struct _Bluedot_IP_Cache _Bluedot_IP_Cache;
struct _Bluedot_IP_Cache
{
    unsigned char ip[MAX_IP_BIT_SIZE];
    char ip_human[INET6_ADDRSTRLEN];
    uint64_t mdate_utime;
    uint64_t cdate_utime;
    uint64_t cache_utime;
    uint8_t code;

    char api_user[BLUEDOT_API_USER];
    char category[BLUEDOT_CATEGORY];
    char comments[BLUEDOT_COMMENTS];
    char source[BLUEDOT_SOURCE];
    char ctime[BLUEDOT_CTIME];
    char mtime[BLUEDOT_MTIME];
    char query[BLUEDOT_QUERY];
    char query_type[BLUEDOT_QUERY_TYPE];
    char last_seen[BLUEDOT_LAST_SEEN];
    uint64_t query_counter;
    uint64_t counter;

    //char json[BLUEDOT_JSON_SIZE];

};

typedef struct _Bluedot_Hash_Cache _Bluedot_Hash_Cache;
struct _Bluedot_Hash_Cache
{
    char hash[SHA256_HASH_SIZE+1];
    uint64_t cache_utime;
//    char bluedot_json[BLUEDOT_JSON_SIZE];
    int alertid;
};


/* IP address to NOT lookup */

typedef struct _Bluedot_Skip _Bluedot_Skip;
struct _Bluedot_Skip
{

    struct
    {
        unsigned char ipbits[MAX_IP_BIT_SIZE];
        unsigned char maskbits[MAX_IP_BIT_SIZE];
    } range;

};

typedef struct _Bluedot_Return _Bluedot_Return;
struct _Bluedot_Return
{
    uint8_t code;
    uint64_t mdate_utime;
    uint64_t cdate_utime;
};


void Bluedot_Init( void );
int Bluedot_Clean_Queue ( const char *json, uint8_t type );
bool Bluedot( struct _JSON_Key_String *JSON_Key_String, uint32_t rule_position, uint8_t s_position, uint16_t json_position, uint16_t json_count );

uint16_t Bluedot_Add_JSON( struct _JSON_Key_String *JSON_Key_String, struct _Bluedot_Return *Bluedot_Return, uint16_t json_count, uint32_t rule_position, uint16_t json_position, uint8_t s_position );

uint16_t Check_IP_Cache ( struct _JSON_Key_String *JSON_Key_String, struct _Bluedot_Return *Bluedot_Return, uint16_t json_count, uint16_t json_position, unsigned char *ip_convert );


void Bluedot_Clean_Cache_Check ( void );
void Bluedot_Clean_Cache( void );
void Bluedot_Load_Categories ( void );
int8_t Bluedot_Category_Lookup( const char *category, char *str, size_t size );

