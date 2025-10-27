#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define UNUSED(x) (void)(x)

// Enable verbose ASN.1 debug prints by defining ASN1_DEBUG (e.g. via compiler flag -DASN1_DEBUG)
#ifndef ASN1_DEBUG
#define ASN1_DEBUG
#endif
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



typedef enum {
    ASN1_RESERVED      = 0x00,
    ASN1_BOOLEAN       = 0x01,
    ASN1_INTEGER       = 0x02,
    ASN1_BIT_STRING    = 0x03,
    ASN1_OCTET_STRING  = 0x04,
    ASN1_NULL          = 0x05,
    ASN1_OBJECT_ID     = 0x06,
    ASN1_SEQUENCE      = 0x30, // constructed
    ASN1_SET           = 0x31, // constructed

    ASN1_LEAVE_CONTAINER = 0xFF

} asn1_tag_t;

typedef enum {
    OID_RESERVED,       // l'id 0 non voglio che sia valido
    OID_AES_256_CBC,    // 2.16.840.1.101.3.4.1.42
    OID_AES_256_WRAP,   // 2.16.840.1.101.3.4.1.45
    OID_ENVELOPED_DATA, // 1.2.840.113549.1.7.3
    OID_SIGNED_DATA,    // 1.2.840.113549.1.7.2
    OID_DATA            // 1.2.840.113549.1.7.1
} asn1_oid_t;

// Forward declaration
struct parsing_context_s;

typedef struct{
    asn1_tag_t tag;
    void (*pre_parse_function)(void);
    int  (*parse_function)(struct parsing_context_s*, void *);
    void  *pDst;
    void (*post_parse_function)(void);
} asn1_parsing_table_t;

struct parsing_context_s{
    asn1_parsing_table_t *parsing_table;

    const uint8_t *buff;
    size_t buff_len;

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

struct octetstring_s {
    size_t len;
    uint8_t data[256];
};

typedef struct asn1_oid_map_s {
    asn1_oid_t oid_enum;
    uint8_t oid_len;
    const uint8_t oid_bytes[20];
} asn1_oid_map_t;

asn1_oid_map_t asn1_oid_map[] = {
    { OID_AES_256_CBC,      9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A } },
    { OID_AES_256_WRAP,     9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D } },
    { OID_ENVELOPED_DATA,   9, { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03 } },
    { OID_SIGNED_DATA,      9, { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 } },
    { OID_DATA,             9, { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 } },
    { 0,                    0, { 0 } } // End marker
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
int get_sequence_set(struct parsing_context_s* this, void* pDst) 
{
    UNUSED(pDst);
    
    if (this == NULL) 
    {
        return -22; // Invalid input
    }

    if (*this->tag_ptr != ASN1_SEQUENCE && *this->tag_ptr != ASN1_SET) 
    {
        return -1; // Not a SEQUENCE or SET
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
    DBG("ENTER %s content_len=%zu content_end_off=%td\n", (this->tag_ptr[0] == ASN1_SEQUENCE) ? "SEQUENCE" : "SET", this->len, (ptrdiff_t)((this->data_ptr + this->len) - this->buff));
    return 0;
}

/**
 * Parses an ASN.1 BIT STRING from the given data.
 * 
 * @param this Pointer to the parsing context.
 * @param pDst Pointer to where the parsed BIT STRING will be stored.
 * 
 * @return 0 on success, negative error code on failure.
 */
int get_bitstring(struct parsing_context_s* this, void* pDst) 
{
    if (this == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }

    if (this->tag_ptr[0] != ASN1_BIT_STRING) 
    {
        return -1; // Not a BIT STRING
    }

    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);//get_bitstring(this->tag_ptr, &this->len);
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

int get_octetstring(struct parsing_context_s* this, void* pDst) 
{
    if (this == NULL || pDst == NULL) 
    {
        return -22; // Invalid input
    }

    if (this->tag_ptr[0] != ASN1_OCTET_STRING) 
    {
        return -1; // Not a OCTET STRING
    }

    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);
    if (this->data_ptr == NULL) 
    {
        return -1; // Invalid length
    }

    struct octetstring_s *os = (struct octetstring_s *)pDst;
    os->len = this->len;
    memcpy(os->data, this->data_ptr, this->len);

    DBG("OCTET STRING len=%zu\n", this->len);
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
    //struct bitstring_s bs1;
    struct octetstring_s os1;
};

struct parsed_data_l1_s {
    bool b1;
    bool b2;
    int i1;
    asn1_oid_t oid1;
    struct parsed_data_l2_s inner_data;
    int i2;
}parsed_data;

asn1_parsing_table_t parsing_table[] = {
    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
        { ASN1_BOOLEAN,     NULL, get_boolean_from_asn1,    &parsed_data.b1,                NULL},
        { ASN1_BOOLEAN,     NULL, get_boolean_from_asn1,    &parsed_data.b2,                NULL},
        { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &parsed_data.i1,                NULL},
        { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &parsed_data.oid1,              NULL},
        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
            { ASN1_OBJECT_ID,       NULL, get_oid_from_asn1,        &parsed_data.inner_data.oid1,   NULL},
            { ASN1_BOOLEAN,         NULL, get_boolean_from_asn1,    &parsed_data.inner_data.b1,     NULL},
            { ASN1_BOOLEAN,         NULL, get_boolean_from_asn1,    &parsed_data.inner_data.b2,     NULL},
            { ASN1_INTEGER,         NULL, get_integer_from_asn1,    &parsed_data.inner_data.i1,     NULL},
            { ASN1_OCTET_STRING,      NULL, get_octetstring,          &parsed_data.inner_data.os1,    NULL},
            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
        { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &parsed_data.i2,                NULL},
        { ASN1_LEAVE_CONTAINER, NULL, NULL,                 NULL,                           NULL},
    { ASN1_RESERVED,    NULL, NULL,                     NULL,                           NULL}
};

struct PKCS_CMS_s
{
    asn1_oid_t              oid_content_type;
    int                     CMS_version;
    int                     KEK_recipient_info_version;
    struct octetstring_s    key_id;
    asn1_oid_t              oid_KEK_algorythm;
    struct octetstring_s    wrapped_key;
    asn1_oid_t              oid_enc_content_info;
    asn1_oid_t              oid_enc_algorythm;
    struct octetstring_s    aes_IV;
    struct octetstring_s    enc_key;
}; 

struct PKCS_CMS_s pkcs7_cms = {0};



/*
┌───────────────────────────────────────────────────────────┐
│ CMS ContentInfo (application/pkcs7-mime)                  │
│ ├─ contentType: id-envelopedData                          │
│ └─ content: EnvelopedData                                 │
│    ├─ version: 4                                          │
│    │                                                      │
│    ├─ recipientInfos: SET OF                              │
│    │  └─ KEKRecipientInfo                                 │
│    │     ├─ version: 4                                    │
│    │     ├─ kekid:                                        │
│    │     │  └─ keyIdentifier: "aes-key-123"               │
│    │     ├─ keyEncryptionAlgorithm:                       │
│    │     │  └─ algorithm: AES-256-WRAP (no params)        │ ← WRAP non ha IV!
│    │     └─ encryptedKey: [40 bytes]                      │ ← Wrapped CEK
│    │                                                      │
│    └─ encryptedContentInfo:                               │
│       ├─ contentType: id-signedData                       │
│       ├─ contentEncryptionAlgorithm:                      │
│       │  ├─ algorithm: AES-256-CBC                        │
│       │  └─ parameters: IV [16 bytes]                     │
│       └─ encryptedContent: [key bytes]                    │
└───────────────────────────────────────────────────────────┘
*/
asn1_parsing_table_t pkcs7_CMS_enveloped_parsing_table[] = 
{
    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
        { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms.oid_content_type,     NULL},
        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
            { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &pkcs7_cms.CMS_version,                NULL},

                { ASN1_SET,    NULL, get_sequence_set,             NULL,                       NULL},
                    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                        { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &pkcs7_cms.KEK_recipient_info_version,                NULL},
                        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                            { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms.key_id,    NULL},
                            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                            { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms.oid_KEK_algorythm,     NULL},
                            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms.wrapped_key,    NULL},
                        { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},

                { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                    { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms.oid_enc_content_info,     NULL},
                    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                        { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms.oid_enc_algorythm,     NULL},
                        { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms.aes_IV,    NULL},
                        { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                    { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms.enc_key,    NULL},                        
                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        
                { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        
            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
        { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
    { ASN1_RESERVED,    NULL, NULL,                     NULL,                           NULL}
};

uint8_t asn1_data[] = { 0x30, 0x29, 
                            0x01, 0x01, 0x00,
                            0x01, 0x01, 0xFF, 
                            0x02, 0x01, 0x42, 
                            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A,
                            0x30, 0x19,
                                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 
                                0x01, 0x01, 0xFF, 
                                0x01, 0x01, 0x00, 
                                0x02, 0x01, 0x55,
                                0x04, 0x05, 0x02, 0xBB, 0xCC, 0xDD, 0xFC,
                            0x02, 0x01, 0x11, 
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
                        //           INTEGER 0x11
                        //           } 
                        // }

uint8_t pkcs7_raw[]=
{
    0x30, 0x82, 0x01, 0x13, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03, 0x30,
    0x82, 0x01, 0x04, 0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x04, 0x31, 0x4B, 0x30, 0x49, 0x02, 0x01,
    0x04, 0x30, 0x0D, 0x04, 0x0B, 0x61, 0x65, 0x73, 0x2D, 0x6B, 0x65, 0x79, 0x2D, 0x30, 0x30, 0x31,
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 0x04, 0x28, 0xB6,
    0xB9, 0xF4, 0x1A, 0xA4, 0x32, 0xF3, 0x04, 0x96, 0xB8, 0x87, 0xFC, 0x63, 0x3B, 0xE3, 0xA6, 0x1C,
    0xF0, 0xCD, 0xA7, 0xAE, 0xBB, 0x04, 0x9C, 0x9D, 0x1C, 0x2C, 0x4E, 0xA7, 0xCC, 0x73, 0x8B, 0xD9,
    0xBE, 0x8B, 0x70, 0xD1, 0xE2, 0xF7, 0x3A, 0x30, 0x81, 0xAD, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x1D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A, 0x04, 0x10, 0x0E, 0x3F, 0x3E, 0x7F, 0x40, 0xF4, 0xFA, 0xD1, 0x67, 0x09, 0x7F, 0xF1,
    0x8B, 0x09, 0xFB, 0x3F, 0x04, 0x81, 0x80, 0xED, 0x4A, 0xF0, 0x96, 0x34, 0x5C, 0x11, 0x86, 0x4B,
    0x0F, 0x7C, 0x42, 0x97, 0xFB, 0x47, 0x72, 0x11, 0x70, 0xC6, 0x5D, 0x17, 0x5E, 0x4E, 0x04, 0xD9,
    0x4F, 0x00, 0xA0, 0xFB, 0xCC, 0x66, 0xFA, 0xBB, 0x97, 0x60, 0x4C, 0xF7, 0xB2, 0xC5, 0x67, 0x20,
    0x14, 0x5D, 0xF9, 0xE8, 0x73, 0xCB, 0xE3, 0xB7, 0x00, 0xA4, 0x14, 0x64, 0xB7, 0x8D, 0x6C, 0x2B,
    0x28, 0x60, 0x2B, 0x24, 0x05, 0xEF, 0xBE, 0xD5, 0x72, 0x78, 0x34, 0x18, 0xA9, 0x48, 0x04, 0x75,
    0xD6, 0x2A, 0x70, 0xFD, 0xFF, 0x27, 0x8E, 0x14, 0x0B, 0xAE, 0x9F, 0x5F, 0x94, 0xD7, 0x14, 0xAD,
    0x5D, 0x0D, 0x47, 0x67, 0x36, 0xD0, 0xD2, 0xC9, 0x75, 0x23, 0xA5, 0x69, 0xB9, 0xE2, 0x97, 0xE0,
    0xB5, 0xC1, 0x69, 0x5A, 0x66, 0x87, 0x09, 0xCF, 0x7D, 0x6C, 0x18, 0x3D, 0xCD, 0x3C, 0x3A, 0x13,
    0x27, 0xFE, 0x59, 0xF4, 0x5D, 0x1B, 0x54
};


struct parsing_context_s init_asn1_parser(asn1_parsing_table_t *parsing_table, const uint8_t *pSrc, size_t buff_len)
{
    struct parsing_context_s context = { 0 };
    
    context.parsing_table = parsing_table;
    context.buff = pSrc;
    context.buff_len = buff_len;
    context.tag_ptr = (uint8_t *)context.buff; // Cast away const for parsing navigation
    context.len = 0;
    context.data_ptr = NULL;

    return context;
}

int main() 
{    
    parsing_context = init_asn1_parser(pkcs7_CMS_enveloped_parsing_table, pkcs7_raw, sizeof(pkcs7_raw));

    for (asn1_parsing_table_t *entry = parsing_context.parsing_table; entry->tag != 0; entry++) 
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

    // // Print parsed data
    // printf("Parsed Data:\n");
    // printf("Outer BOOLEAN 1: %s\n", parsed_data.b1 ? "TRUE" : "FALSE");
    // printf("Outer BOOLEAN 2: %s\n", parsed_data.b2 ? "TRUE" : "FALSE");
    // printf("Outer INTEGER 1: %d\n", parsed_data.i1);
    // printf("Outer OID 1: %d (%s)\n", parsed_data.oid1,
    //        (parsed_data.oid1 == OID_AES_256_CBC) ? "AES-256-CBC" :
    //        (parsed_data.oid1 == OID_AES_256_WRAP) ? "AES-256-WRAP" : "Unknown");
    // printf("\tInner OID 1: %d (%s)\n", parsed_data.inner_data.oid1,
    //        (parsed_data.inner_data.oid1 == OID_AES_256_CBC) ? "AES-256-CBC" :
    //        (parsed_data.inner_data.oid1 == OID_AES_256_WRAP) ? "AES-256-WRAP" : "Unknown");
    // printf("\tInner BOOLEAN 1: %s\n", parsed_data.inner_data.b1 ? "TRUE" : "FALSE");
    // printf("\tInner BOOLEAN 2: %s\n", parsed_data.inner_data.b2 ? "TRUE" : "FALSE");
    // printf("\tInner INTEGER 1: %d\n", parsed_data.inner_data.i1);
    // // printf("\tInner BIT STRING 1: (%d) ", parsed_data.inner_data.bs1.unused_bits);
    // // for (size_t i = 0; i < parsed_data.inner_data.bs1.len; i++) 
    // // {
    // //     printf("%02X ", parsed_data.inner_data.bs1.data[i]);
    // // }
    // printf("\tInner OCTET STRING 1: ");
    // for (size_t i = 0; i < parsed_data.inner_data.os1.len; i++) 
    // {
    //     printf("%02X ", parsed_data.inner_data.os1.data[i]);
    // }
    // printf("\n");
    // printf("Outer INTEGER 2: %d\n", parsed_data.i2);

    return 0;
}