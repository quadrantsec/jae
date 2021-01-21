


typedef struct _After _After;
struct _After
{

    uint32_t hash;

    char key[MAX_JSON_KEY];
    char json[MAX_JSON_VALUE];

    uint64_t timestamp;
    uint16_t expire;

    uint64_t signature_id;
    char signature_desc[MAX_JSON_VALUE];

    uint32_t revision;


};


bool After( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position );

