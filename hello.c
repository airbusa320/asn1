#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define UNUSED(x) (void)(x)

// Enable verbose ASN.1 debug prints by defining ASN1_DEBUG (e.g. via compiler flag -DASN1_DEBUG)
#define ASN1_DEBUG
#ifdef ASN1_DEBUG
#define DBG(fmt, ...) printf("[ASN1][depth=%u][off=%td] " fmt, parsing_context.nest_idx, (ptrdiff_t)(parsing_context.tag_ptr - parsing_context.buff), ##__VA_ARGS__)
#else
#define DBG(fmt, ...) do {} while(0)
#endif


#define MAX_NESTING_DEPTH 8

// ASN.1

/*
UNIVERSAL 0             Reserved for use by the encoding rules
UNIVERSAL 1             Boolean type
UNIVERSAL 2             Integer type
UNIVERSAL 3             Bitstring type
UNIVERSAL 4             Octetstring type
UNIVERSAL 5             Null type
UNIVERSAL 6             Object identifier type
UNIVERSAL 7             Object descriptor type
UNIVERSAL 8             External type and Instance-of type
UNIVERSAL 9             Real type
UNIVERSAL 10            Enumerated type
UNIVERSAL 11            Embedded-pdv type
UNIVERSAL 12            UTF8String type
UNIVERSAL 13            Relative object identifier type
UNIVERSAL 14            The time type
UNIVERSAL 15            Reserved for future editions of this Recommendation | International Standard
UNIVERSAL 16            Sequence and Sequence-of types
UNIVERSAL 17            Set and Set-of types
UNIVERSAL 18-22, 25-30  Character string types
UNIVERSAL 23-24         UTCTime and GeneralizedTime
UNIVERSAL 31-34         DATE, TIME-OF-DAY, DATE-TIME and DURATION respectively
UNIVERSAL 35            OID internationalized resource identifier type
UNIVERSAL 36            Relative OID internationalized resource identifier type
UNIVERSAL 37-...        Reserved for addenda to this Recommendation | International Standard
*/

struct parsing_context_s{
    uint8_t *buff;
    uint8_t buff_len;

    uint8_t *tag_ptr;        // current tag pointer
    size_t len;              // length of current field data
    uint8_t *data_ptr;       // pointer to current field data (after length bytes)

    uint8_t nest_idx;        // current nesting depth (number of open SEQUENCE/SET containers)
    uint8_t *container_end[MAX_NESTING_DEPTH]; // stack of end pointers for open containers (content end addresses)
} parsing_context = { 0 };


struct bitstring_s {
    size_t len;
    uint8_t unused_bits;
    uint8_t data[256];
};

typedef enum {
    ASN1_RESERVED      = 0x00,
    ASN1_BOOLEAN       = 0x01,
    ASN1_INTEGER       = 0x02,
    ASN1_BIT_STRING    = 0x03,
    ASN1_OCTET_STRING  = 0x04,
    ASN1_NULL          = 0x05,
    ASN1_OBJECT_ID     = 0x06,
    ASN1_SEQUENCE      = 0x30, // constructed
    ASN1_SET           = 0x31  // constructed

} asn1_tag_t;

typedef enum {
    OID_RESERVED,
    OID_AES_256_CBC,    // 2.16.840.1.101.3.4.1.42
    OID_AES_256_WRAP    // 2.16.840.1.101.3.4.1.45
} asn1_oid_t;

typedef struct asn1_oid_map_s {
    asn1_oid_t oid_enum;
    uint8_t oid_len;
    const uint8_t oid_bytes[20];
} asn1_oid_map_t;

asn1_oid_map_t asn1_oid_map[] = {
    { OID_AES_256_CBC,  9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A } },
    { OID_AES_256_WRAP, 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D } },
    { 0, 0, { 0 } } // End marker
};

#define MAX_BYTE_LEN 4 // 4byte 32bit

asn1_tag_t get_asn1_tag(const unsigned char *data, unsigned char *pDst)
{
    if (data == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }

    *pDst = data[0];
    return 0;
}

//ritorna il puntatore all'inizio del dato e setta pDst con la lunghezza del dato
/**
 * Parses ASN.1 length from the given data.
 * 
 * @param data Pointer to the ASN.1 encoded len field.
 * @param pDst Pointer to size_t where the parsed length will be stored.
 * 
 * @return Pointer to the position in data after the length bytes, or NULL on error.
 */
unsigned char *get_asn1_len(const unsigned char *data, size_t *pDst)
{
    if (data == NULL || pDst == NULL) 
    {
        return NULL; // Invalid input
    }

    if (data[0] < 0x80) 
    {
        *pDst = data[0];
        return (unsigned char *)(data + 1);
    } 
    else 
    {
        size_t num_bytes = data[0] & 0x7F;
        if (num_bytes > sizeof(size_t) || num_bytes > MAX_BYTE_LEN) 
        {
            return NULL; // Length too large
        }

        *pDst = 0;
        for (size_t i = 0; i < num_bytes; i++) 
        {
            *pDst = (*pDst << 8) | data[1 + i];
        }

        

        return (unsigned char *)(data + 1 + num_bytes);
    }
}

/**
 * Parses an ASN.1 BOOLEAN from the given data.
 * 
 * @param this Pointer to the parsing context.
 * @param pDst Pointer to bool where the parsed BOOLEAN will be stored.
 * 
 * @return 0 on success, negative error code on failure.
 */
int get_boolean_from_asn1(struct parsing_context_s* this, void *pDst) 
{
    if (this == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }
    
    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);

    if (this->data_ptr == NULL || this->len != 1) 
    {
        return -1; // Invalid length
    }

    bool *value = (bool *)pDst;
    *value = (this->data_ptr[0] != 0) ? true : false;

    if (this->data_ptr[0] != 0 && this->data_ptr[0] != 0xFF) 
    {
        return -1; // Invalid BOOLEAN encoding
    }
    DBG("BOOLEAN value=%s len=%zu\n", *value ? "TRUE" : "FALSE", this->len);
    return 0;
}

/**
 * Parses an ASN.1 INTEGER from the given data.
 * 
 * @param this Pointer to the parsing context.
 * @param pDst Pointer to int where the parsed INTEGER will be stored.
 * 
 * @return 0 on success, negative error code on failure.
 */
int get_integer_from_asn1(struct parsing_context_s* this, void *pDst) 
{
    if (this == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }
    
    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);
    if (this->data_ptr == NULL || this->len == 0 || this->len > sizeof(int)) 
    {
        return -1; // Invalid length
    }

    int *value = (int *)pDst;
    *value = 0;
    for (size_t i = 0; i < this->len; i++) 
    {
        *value = (*value << 8) | this->data_ptr[i];
    }
    DBG("INTEGER value=%d len=%zu\n", *value, this->len);
    return 0;
}

/**
 * Parses an ASN.1 SEQUENCE from the given data.
 * 
 * @param this Pointer to the parsing context.
 * @param pDst Unused (SEQUENCE has no data to store).
 * 
 * @return 0 on success, negative error code on failure.
 */
int get_sequence(struct parsing_context_s* this, void* pDst) 
{
    UNUSED(pDst);
    
    if (this == NULL) 
    {
        return -22; // Invalid input
    }

    if (*this->tag_ptr != 0x30) 
    {
        return -1; // Not a SEQUENCE
    }

    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);
    if (this->data_ptr == NULL) 
    {
        return -1; // Invalid SEQUENCE
    }
    // Store end pointer of current container at current depth (before increment in main loop)
    if (this->nest_idx < (sizeof(this->container_end)/sizeof(this->container_end[0]))) {
        this->container_end[this->nest_idx] = this->data_ptr + this->len; // end of content inside sequence
    } else {
        return -1; // nesting too deep
    }
    DBG("ENTER SEQUENCE content_len=%zu content_end_off=%td\n", this->len, (ptrdiff_t)((this->data_ptr + this->len) - this->buff));
    return 0;
}

uint8_t *get_bitstring(const uint8_t *data, size_t *length) 
{
    if (data == NULL || length == NULL) 
    {
        return NULL; // Invalid input
    }

    if (data[0] != ASN1_BIT_STRING) 
    {
        return NULL; // Not a BIT STRING
    }

    unsigned char *next = get_asn1_len(data + 1, length);
    if (next == NULL) 
    {
        return NULL; // Invalid length
    }

    return next;
}

/**
 * Parses an ASN.1 BIT STRING from the given data.
 * 
 * @param this Pointer to the parsing context.
 * @param pDst Pointer to where the parsed BIT STRING will be stored.
 * 
 * @return 0 on success, negative error code on failure.
 */
int get_bitstring_2(struct parsing_context_s* this, void* pDst) 
{
    if (this == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }

    if (this->tag_ptr[0] != ASN1_BIT_STRING) 
    {
        return -1; // Not a BIT STRING
    }

    this->data_ptr = get_bitstring(this->tag_ptr, &this->len);
    if (this->data_ptr == NULL) 
    {
        return -1; // Invalid length
    }

    struct bitstring_s *bs = (struct bitstring_s *)pDst;
    bs->len = this->len - 1; // Exclude the unused bits byte
    bs->unused_bits = this->data_ptr[0];

    // First byte of BIT STRING is the number of unused bits in the last byte
    // Skip it and copy the actual bitstring data
    if (this->len > 0) 
    {
        memcpy(bs->data, this->data_ptr + 1, this->len - 1);
    }
    DBG("BIT STRING unused_bits=%u bytes=%zu\n", bs->unused_bits, bs->len);
    return 0;
}

/**
 * Parses an ASN.1 OBJECT IDENTIFIER from the given data.
 * 
 * @param this Pointer to the parsing context.
 * @param pDst Pointer to where the parsed OBJECT IDENTIFIER will be stored.
 * 
 * @return 0 on success, negative error code on failure.
 */
int get_oid_from_asn1(struct parsing_context_s* this, void* pDst) 
{
    if (this == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }

    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);
    if (this->data_ptr == NULL) 
    {
        return -1; // OID not found
    }

    // cerca l'OID nella mappa con memcmp
    *(asn1_oid_t *)pDst = OID_RESERVED;
    for (int i = 0; asn1_oid_map[i].oid_len != 0; i++) 
    {
        if (this->len == asn1_oid_map[i].oid_len) 
        {
            if (memcmp(this->data_ptr, asn1_oid_map[i].oid_bytes, this->len) == 0) 
            {
                *(asn1_oid_t *)pDst = asn1_oid_map[i].oid_enum;
                break;
            }
        }
    }
    DBG("OID len=%zu value_enum=%d\n", this->len, *(asn1_oid_t *)pDst);

    return 0;
}

struct parsed_data_l2_s
{
    asn1_oid_t oid1;
    bool b1;
    bool b2;
    int i1;
    struct bitstring_s bs1;
};

struct parsed_data_l1_s {
    bool b1;
    bool b2;
    int i1;
    asn1_oid_t oid1;
    struct parsed_data_l2_s inner_data;
}parsed_data;

typedef struct{
    asn1_tag_t tag;
    void (*pre_parse_function)(void);
    int  (*parse_function)(struct parsing_context_s*, void *);
    void  *pDst;
    void (*post_parse_function)(void);
} asn1_parsing_table_t;

asn1_parsing_table_t parsing_table[] = {
    { ASN1_SEQUENCE,    NULL, get_sequence,             NULL,                           NULL},
    { ASN1_BOOLEAN,     NULL, get_boolean_from_asn1,    &parsed_data.b1,                NULL},
    { ASN1_BOOLEAN,     NULL, get_boolean_from_asn1,    &parsed_data.b2,                NULL},
    { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &parsed_data.i1,                NULL},
    { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &parsed_data.oid1,              NULL},
    { ASN1_SEQUENCE,    NULL, get_sequence,             NULL,                           NULL},
    { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &parsed_data.inner_data.oid1,   NULL},
    { ASN1_BOOLEAN,     NULL, get_boolean_from_asn1,    &parsed_data.inner_data.b1,     NULL},
    { ASN1_BOOLEAN,     NULL, get_boolean_from_asn1,    &parsed_data.inner_data.b2,     NULL},
    { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &parsed_data.inner_data.i1,     NULL},
    { ASN1_BIT_STRING,  NULL, get_bitstring_2,          &parsed_data.inner_data.bs1,    NULL},
    { ASN1_RESERVED,    NULL, NULL,                     NULL,                           NULL}
};


int main() 
{
    uint8_t asn1_data[] = { 0x30, 0x26, 
                                0x01, 0x01, 0x00,
                                0x01, 0x01, 0xFF, 
                                0x02, 0x01, 0x42, 
                                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A,
                                0x30, 0x19,
                                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 
                                    0x01, 0x01, 0xFF, 
                                    0x01, 0x01, 0x00, 
                                    0x02, 0x01, 0x55,
                                    0x03, 0x05, 0x02, 0xBB, 0xCC, 0xDD, 0xFC
                        }; // SEQUENCE { 
                           //           BOOLEAN FALSE, 
                           //           BOOLEAN TRUE, 
                           //           INTEGER 0x42, 
                           //           OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.42
                           //           SEQUENCE { 
                           //                   OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.45
                           //                   BOOLEAN FALSE, 
                           //                   BOOLEAN TRUE, 
                           //                   INTEGER 0x55, 
                           //                   BITSTRING { 0x02 0xBB 0xCC 0xDD 0xFC } 
                           //           } 
                           // }
                           
    uint8_t buff_len = sizeof(asn1_data);
    UNUSED(buff_len);

    parsing_context.buff = asn1_data;
    parsing_context.buff_len = sizeof(asn1_data);
    parsing_context.tag_ptr = asn1_data;
    parsing_context.len = 0;
    parsing_context.data_ptr = NULL;

    for (asn1_parsing_table_t *entry = parsing_table; entry->tag != 0; entry++) 
    {
        if(entry->pre_parse_function != NULL) 
        {
            entry->pre_parse_function();
        }

        if (entry->parse_function != NULL)
        {
            DBG("PARSE tag=0x%02X\n", entry->tag);
            entry->parse_function(&parsing_context, entry->pDst);
            // Advance tag_ptr to next field
            // For SEQUENCE and SET, data_ptr points inside the structure, so just move there
            // For other types, data_ptr points to the data, so skip over it
            if (entry->tag == ASN1_SEQUENCE || entry->tag == ASN1_SET) 
            {
                // Entering container: increment depth and move to first inner tag
                parsing_context.nest_idx++;
                parsing_context.tag_ptr = parsing_context.data_ptr;
            }
            else
            {
                // Advance past primitive/constructed but non-container field
                parsing_context.tag_ptr = parsing_context.data_ptr + parsing_context.len;
            }
            DBG("ADVANCED off=%td\n", (ptrdiff_t)(parsing_context.tag_ptr - parsing_context.buff));
            // After advancing, check if we've reached end of one or more containers and pop them
            while (parsing_context.nest_idx > 0 && parsing_context.tag_ptr >= parsing_context.container_end[parsing_context.nest_idx - 1]) {
                DBG("LEAVE CONTAINER depth_before=%u end_off=%td\n", parsing_context.nest_idx, (ptrdiff_t)(parsing_context.container_end[parsing_context.nest_idx - 1] - parsing_context.buff));
                parsing_context.nest_idx--;
            }
        }
        if (entry->post_parse_function != NULL) 
        {
            entry->post_parse_function();
        }
    }

    // Print parsed data
    printf("Parsed Data:\n");
    printf("Outer BOOLEAN 1: %s\n", parsed_data.b1 ? "TRUE" : "FALSE");
    printf("Outer BOOLEAN 2: %s\n", parsed_data.b2 ? "TRUE" : "FALSE");
    printf("Outer INTEGER 1: %d\n", parsed_data.i1);
    printf("Outer OID 1: %d (%s)\n", parsed_data.oid1,
           (parsed_data.oid1 == OID_AES_256_CBC) ? "AES-256-CBC" :
           (parsed_data.oid1 == OID_AES_256_WRAP) ? "AES-256-WRAP" : "Unknown");
    printf("\tInner OID 1: %d (%s)\n", parsed_data.inner_data.oid1,
           (parsed_data.inner_data.oid1 == OID_AES_256_CBC) ? "AES-256-CBC" :
           (parsed_data.inner_data.oid1 == OID_AES_256_WRAP) ? "AES-256-WRAP" : "Unknown");
    printf("\tInner BOOLEAN 1: %s\n", parsed_data.inner_data.b1 ? "TRUE" : "FALSE");
    printf("\tInner BOOLEAN 2: %s\n", parsed_data.inner_data.b2 ? "TRUE" : "FALSE");
    printf("\tInner INTEGER 1: %d\n", parsed_data.inner_data.i1);
    printf("\tInner BIT STRING 1: (%d) ", parsed_data.inner_data.bs1.unused_bits);
    for (size_t i = 0; i < parsed_data.inner_data.bs1.len; i++) 
    {
        printf("%02X ", parsed_data.inner_data.bs1.data[i]);
    }
    printf("\n");

    return 0;
}