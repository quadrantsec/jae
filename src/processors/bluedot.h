

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


typedef struct _Bluedot_IP_Queue _Bluedot_IP_Queue;
struct _Bluedot_IP_Queue
{
    unsigned char ip[MAX_IP_BIT_SIZE];
};

typedef struct _Bluedot_IP_Cache _Bluedot_IP_Cache;
struct _Bluedot_IP_Cache
{
    unsigned char ip[MAX_IP_BIT_SIZE];
    uint64_t mdate_utime;
    uint64_t cdate_utime;
    uint64_t cache_utime;
    char json[BLUEDOT_JSON_SIZE];
    uint8_t code;
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


void Bluedot_Clean_Cache_Check ( void );
void Bluedot_Clean_Cache( void );

