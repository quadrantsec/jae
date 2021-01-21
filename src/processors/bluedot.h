
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


typedef struct _Bluedot_IP_Queue _Bluedot_IP_Queue;
struct _Bluedot_IP_Queue
{
    unsigned char ip[MAX_IP_BIT_SIZE];
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


void Bluedot_Init( void );
bool Bluedot( uint32_t rule_position, uint8_t s_position, char *json );

