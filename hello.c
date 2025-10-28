#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define UNUSED(x) (void)(x)

// Enable verbose ASN.1 debug prints by defining ASN1_DEBUG (e.g. via compiler flag -DASN1_DEBUG)
// #ifndef ASN1_DEBUG
// #define ASN1_DEBUG
// #endif
// #ifdef ASN1_DEBUG
// #define DBG(fmt, ...) printf("[ASN1][depth=%u][off=%td] " fmt, parsing_context.nest_idx, (ptrdiff_t)(parsing_context.tag_ptr - parsing_context.buff), ##__VA_ARGS__)
// #else
// #define DBG(fmt, ...) do {} while(0)
// #endif


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

    const uint8_t *tag_ptr;  // current tag pointer
    size_t len;              // length of current field data
    const uint8_t *data_ptr; // pointer to current field data (after length bytes)

    uint8_t nest_idx;        // current nesting depth (number of open SEQUENCE/SET containers)
    uint8_t *container_end[MAX_NESTING_DEPTH]; // stack of end pointers for open containers (content end addresses)
};


struct bitstring_s {
    size_t len;
    uint8_t unused_bits;
    uint8_t data[256];
};

struct octetstring_s {
    size_t len;
    uint8_t data[256];
};

struct certificate_s {
    size_t len;
    uint8_t data[2048];
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
    // DBG("BOOLEAN value=%s len=%zu\n", *value ? "TRUE" : "FALSE", this->len);
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
    // DBG("INTEGER value=%d len=%zu\n", *value, this->len);
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
    if (this == NULL) 
    {
        return -22; // Invalid input
    }

    if (*this->tag_ptr != ASN1_SEQUENCE && *this->tag_ptr != ASN1_SET) 
    {
        return -1; // Not a SEQUENCE or SET
    }

    if (pDst){
        printf("save SEQUENCE\n");
    }

    this->data_ptr = get_asn1_len(this->tag_ptr + 1, &this->len);
    if (this->data_ptr == NULL) 
    {
        return -1; // Invalid SEQUENCE
    }
    // Store end pointer of current container at current depth (before increment in main loop)
    if (this->nest_idx < (sizeof(this->container_end)/sizeof(this->container_end[0]))) {
        this->container_end[this->nest_idx] = this->data_ptr + this->len; // end of content inside sequence
        this->nest_idx++;
    } else {
        return -1; // nesting too deep
    }

    if(pDst != NULL)
    {
        struct certificate_s *pCertificate = (struct certificate_s *)pDst;
        pCertificate->len = this->len;
        memcpy(pCertificate->data, this->tag_ptr, this->len + (this->data_ptr - this->tag_ptr));
    }

    // DBG("ENTER %s content_len=%zu content_end_off=%td\n", (this->tag_ptr[0] == ASN1_SEQUENCE) ? "SEQUENCE" : "SET", this->len, (ptrdiff_t)((this->data_ptr + this->len) - this->buff));
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
    // DBG("BIT STRING unused_bits=%u bytes=%zu\n", bs->unused_bits, bs->len);
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

    // DBG("OCTET STRING len=%zu\n", this->len);
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
    // DBG("OID len=%zu value_enum=%d\n", this->len, *(asn1_oid_t *)pDst);

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

struct PKCS_CMS_s pkcs7_cms_parsed_data = {0};



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
        { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms_parsed_data.oid_content_type,     NULL},
        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
            { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &pkcs7_cms_parsed_data.CMS_version,                NULL},

                { ASN1_SET,    NULL, get_sequence_set,             NULL,                       NULL},
                    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                        { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &pkcs7_cms_parsed_data.KEK_recipient_info_version,                NULL},
                        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                            { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms_parsed_data.key_id,    NULL},
                            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                            { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms_parsed_data.oid_KEK_algorythm,     NULL},
                            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms_parsed_data.wrapped_key,    NULL},
                        { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},

                { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                    { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms_parsed_data.oid_enc_content_info,     NULL},
                    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                       NULL},
                        { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_cms_parsed_data.oid_enc_algorythm,     NULL},
                        { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms_parsed_data.aes_IV,    NULL},
                        { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                    { ASN1_OCTET_STRING,      NULL, get_octetstring,          &pkcs7_cms_parsed_data.enc_key,    NULL},                        
                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        
                { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                        
            { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
        { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
    { ASN1_RESERVED,    NULL, NULL,                     NULL,                           NULL}
};



struct PKCS_certs_only_s
{
    asn1_oid_t              oid_content_type;
    int                     CMS_version;
    asn1_oid_t              oid_encapsulated_content_info;
    struct certificate_s    certificates[2];
}; 

struct PKCS_certs_only_s pkcs7_certs_only_parsed_data = {0};

asn1_parsing_table_t pkcs7_certs_only[] =
{
    { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
        { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_certs_only_parsed_data.oid_content_type,     NULL},
        { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
            { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
            
                { ASN1_INTEGER,     NULL, get_integer_from_asn1,    &pkcs7_certs_only_parsed_data.CMS_version,                NULL},
                { ASN1_SET,    NULL, get_sequence_set,             NULL,                           NULL},
                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
                    { ASN1_OBJECT_ID,   NULL, get_oid_from_asn1,        &pkcs7_certs_only_parsed_data.oid_encapsulated_content_info,     NULL},
                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                
                { ASN1_SEQUENCE,    NULL, get_sequence_set,             NULL,                           NULL},
                    // certificati
                    { ASN1_SEQUENCE,    NULL, get_sequence_set,             &pkcs7_certs_only_parsed_data.certificates[0],                           NULL},
                    { ASN1_SEQUENCE,    NULL, get_sequence_set,             &pkcs7_certs_only_parsed_data.certificates[1],                           NULL},

                    { ASN1_LEAVE_CONTAINER, NULL, NULL,                     NULL,                           NULL},
                
                { ASN1_SET,    NULL, get_sequence_set,             NULL,                           NULL},
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

uint8_t pkcs7_certs_only_raw[]=
{
0x30, 0x82, 0x06, 0x32, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0x30, 
0x82, 0x06, 0x23, 0x30, 0x82, 0x06, 0x1F, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x0B, 0x06, 0x09, 
0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x82, 0x06, 0x07, 0x30, 0x82, 0x02, 
0x8C, 0x30, 0x82, 0x02, 0x12, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x12, 0xFA, 0xBE, 0xE7, 
0xFE, 0x81, 0x81, 0x26, 0xC8, 0x0C, 0x34, 0x03, 0x30, 0x44, 0xEB, 0x53, 0x60, 0x59, 0x2D, 0xC2, 
0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x81, 0x80, 0x31, 
0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31, 0x0E, 0x30, 0x0C, 
0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x05, 0x49, 0x74, 0x61, 0x6C, 0x79, 0x31, 0x1A, 0x30, 0x18, 
0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x11, 0x52, 0x69, 0x70, 0x61, 0x74, 0x72, 0x61, 0x6E, 0x73, 
0x6F, 0x6E, 0x65, 0x20, 0x28, 0x41, 0x50, 0x29, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 
0x0A, 0x0C, 0x16, 0x4B, 0x73, 0x65, 0x6E, 0x69, 0x61, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 
0x74, 0x79, 0x20, 0x53, 0x2E, 0x70, 0x2E, 0x41, 0x2E, 0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 
0x04, 0x0B, 0x0C, 0x03, 0x52, 0x26, 0x44, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 
0x0C, 0x0D, 0x4B, 0x53, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x52, 0x31, 0x30, 
0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x38, 0x32, 0x38, 0x31, 0x35, 0x30, 0x39, 0x35, 0x32, 0x5A, 
0x17, 0x0D, 0x34, 0x35, 0x30, 0x38, 0x32, 0x33, 0x31, 0x35, 0x30, 0x39, 0x35, 0x32, 0x5A, 0x30, 
0x81, 0x82, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31, 
0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x16, 0x4B, 0x73, 0x65, 0x6E, 0x69, 0x61, 
0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x53, 0x2E, 0x70, 0x2E, 0x41, 0x2E, 
0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x03, 0x52, 0x26, 0x44, 0x31, 0x0E, 
0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x05, 0x49, 0x74, 0x61, 0x6C, 0x79, 0x31, 0x18, 
0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0F, 0x4B, 0x53, 0x20, 0x44, 0x65, 0x76, 0x69, 
0x63, 0x65, 0x20, 0x43, 0x41, 0x20, 0x52, 0x31, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 
0x07, 0x13, 0x11, 0x52, 0x69, 0x70, 0x61, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x6F, 0x6E, 0x65, 0x20, 
0x28, 0x41, 0x50, 0x29, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 
0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xEF, 
0x66, 0x88, 0x08, 0x09, 0xF3, 0xE1, 0x18, 0x1F, 0x6E, 0x68, 0xAA, 0xF9, 0x3C, 0x65, 0x1F, 0x88, 
0xA6, 0x11, 0x37, 0xA0, 0x73, 0xA2, 0xF0, 0xD3, 0x06, 0x95, 0x42, 0xB4, 0x0D, 0x73, 0xB5, 0xAA, 
0x93, 0x3B, 0x29, 0xB3, 0x45, 0x1E, 0x49, 0x98, 0xDC, 0x7B, 0xC2, 0xD5, 0xA3, 0xF3, 0x55, 0x77, 
0x00, 0xAD, 0xB7, 0x18, 0xDE, 0xEC, 0x66, 0x8F, 0x70, 0xB1, 0x55, 0xE7, 0xD9, 0xF9, 0xEA, 0xA3, 
0x66, 0x30, 0x64, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x5F, 0x6D, 
0x58, 0x52, 0xF7, 0xE7, 0x9B, 0xE1, 0x03, 0xD2, 0xB1, 0x76, 0x2D, 0xB3, 0xEA, 0xA9, 0xBC, 0x8F, 
0xF1, 0xA9, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xAA, 
0x27, 0x84, 0xA9, 0x57, 0x1D, 0x14, 0x07, 0xC0, 0x50, 0x1A, 0xB1, 0xBC, 0x81, 0x96, 0x4D, 0x38, 
0xC5, 0x96, 0x8E, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08, 0x30, 
0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 
0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 
0x04, 0x03, 0x02, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xEE, 0x3B, 0xEC, 0x2F, 0x9C, 
0x2E, 0x2C, 0x08, 0xA4, 0x44, 0xD5, 0x42, 0xBA, 0xE0, 0x29, 0x61, 0xC1, 0xE0, 0x5D, 0xBF, 0x2F, 
0x2A, 0x8F, 0xB8, 0x73, 0xEB, 0xB7, 0x3C, 0xFC, 0x9B, 0x72, 0x77, 0x31, 0x09, 0xA4, 0x7B, 0xAE, 
0x41, 0xAA, 0x5E, 0x2B, 0x43, 0xE7, 0x15, 0xD4, 0x45, 0x20, 0x1C, 0x02, 0x30, 0x4E, 0xA5, 0xAC, 
0x8C, 0x93, 0x88, 0xC5, 0x4C, 0x71, 0x8C, 0xAA, 0x4D, 0xE8, 0xB1, 0xF9, 0xD8, 0x0A, 0x4A, 0xB5, 
0x3B, 0x06, 0xF3, 0xC8, 0xDA, 0xE5, 0x6C, 0xAC, 0x7A, 0xFE, 0xFA, 0xE9, 0x36, 0x73, 0x1E, 0x3E, 
0xC2, 0x06, 0xC3, 0x11, 0xD8, 0xC0, 0xD9, 0x81, 0xDB, 0x15, 0x9A, 0x31, 0x8A, 0x30, 0x82, 0x03, 
0x73, 0x30, 0x82, 0x03, 0x1A, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x58, 0x20, 0xEC, 0x82, 
0x9A, 0xFE, 0x61, 0x1B, 0xED, 0x2B, 0xCE, 0xD9, 0x18, 0x6E, 0x00, 0x40, 0x1F, 0x8D, 0x45, 0x72, 
0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x81, 0x82, 0x31, 
0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31, 0x1F, 0x30, 0x1D, 
0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x16, 0x4B, 0x73, 0x65, 0x6E, 0x69, 0x61, 0x20, 0x53, 0x65, 
0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x53, 0x2E, 0x70, 0x2E, 0x41, 0x2E, 0x31, 0x0C, 0x30, 
0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x03, 0x52, 0x26, 0x44, 0x31, 0x0E, 0x30, 0x0C, 0x06, 
0x03, 0x55, 0x04, 0x08, 0x13, 0x05, 0x49, 0x74, 0x61, 0x6C, 0x79, 0x31, 0x18, 0x30, 0x16, 0x06, 
0x03, 0x55, 0x04, 0x03, 0x13, 0x0F, 0x4B, 0x53, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 
0x43, 0x41, 0x20, 0x52, 0x31, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x11, 
0x52, 0x69, 0x70, 0x61, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x6F, 0x6E, 0x65, 0x20, 0x28, 0x41, 0x50, 
0x29, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x31, 0x30, 0x30, 0x33, 0x31, 0x34, 0x34, 0x39, 0x30, 
0x30, 0x5A, 0x17, 0x0D, 0x32, 0x38, 0x31, 0x30, 0x30, 0x33, 0x30, 0x38, 0x34, 0x39, 0x30, 0x30, 
0x5A, 0x30, 0x2D, 0x31, 0x2B, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x41, 0x34, 
0x35, 0x38, 0x30, 0x46, 0x39, 0x30, 0x30, 0x30, 0x46, 0x30, 0x2E, 0x69, 0x64, 0x65, 0x6E, 0x74, 
0x69, 0x74, 0x79, 0x2E, 0x70, 0x61, 0x6E, 0x65, 0x6C, 0x2E, 0x6B, 0x73, 0x2E, 0x69, 0x6F, 0x74, 
0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 
0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xE1, 0xFE, 0x76, 0xAF, 0x23, 
0x2B, 0xB2, 0xA2, 0x8E, 0x05, 0x93, 0xB5, 0x2D, 0xEB, 0x89, 0x6F, 0x56, 0xB9, 0x8C, 0x57, 0x82, 
0x3D, 0x1F, 0x5A, 0x89, 0x4D, 0x36, 0x6F, 0x5A, 0x92, 0x87, 0x34, 0x4D, 0xB9, 0xAF, 0xF0, 0x7C, 
0x43, 0xDE, 0xDF, 0x6B, 0x3F, 0x8B, 0xD5, 0xA1, 0x53, 0xF1, 0xEA, 0x5C, 0xDF, 0x13, 0x2A, 0x91, 
0x75, 0x68, 0xBF, 0x50, 0x19, 0xF9, 0xF6, 0x80, 0xCF, 0x11, 0x9E, 0xA3, 0x82, 0x01, 0xC0, 0x30, 
0x82, 0x01, 0xBC, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x61, 
0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x5A, 0x30, 0x58, 0x30, 0x56, 0xA0, 0x54, 0xA0, 0x52, 0x86, 
0x50, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x65, 0x75, 0x2E, 0x69, 0x6E, 0x66, 0x69, 
0x73, 0x69, 0x63, 0x61, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x61, 0x70, 0x69, 0x2F, 0x76, 0x31, 
0x2F, 0x70, 0x6B, 0x69, 0x2F, 0x63, 0x72, 0x6C, 0x2F, 0x33, 0x35, 0x61, 0x64, 0x32, 0x39, 0x33, 
0x31, 0x2D, 0x62, 0x39, 0x66, 0x36, 0x2D, 0x34, 0x62, 0x63, 0x66, 0x2D, 0x62, 0x35, 0x62, 0x38, 
0x2D, 0x62, 0x63, 0x65, 0x35, 0x61, 0x61, 0x64, 0x35, 0x30, 0x31, 0x32, 0x61, 0x2F, 0x64, 0x65, 
0x72, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x5F, 0x6D, 
0x58, 0x52, 0xF7, 0xE7, 0x9B, 0xE1, 0x03, 0xD2, 0xB1, 0x76, 0x2D, 0xB3, 0xEA, 0xA9, 0xBC, 0x8F, 
0xF1, 0xA9, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xD8, 0x9D, 0x47, 
0x66, 0x1C, 0x04, 0x7B, 0x7C, 0x08, 0x43, 0xDB, 0x64, 0x62, 0x8C, 0xDF, 0x02, 0xC7, 0xB7, 0x51, 
0x52, 0x30, 0x81, 0xA1, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x81, 
0x94, 0x30, 0x81, 0x91, 0x30, 0x81, 0x8E, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 
0x02, 0x86, 0x81, 0x81, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x65, 0x75, 0x2E, 0x69, 
0x6E, 0x66, 0x69, 0x73, 0x69, 0x63, 0x61, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x61, 0x70, 0x69, 
0x2F, 0x76, 0x31, 0x2F, 0x70, 0x6B, 0x69, 0x2F, 0x63, 0x61, 0x2F, 0x65, 0x64, 0x30, 0x31, 0x64, 
0x66, 0x34, 0x37, 0x2D, 0x62, 0x65, 0x38, 0x35, 0x2D, 0x34, 0x31, 0x31, 0x37, 0x2D, 0x39, 0x62, 
0x66, 0x65, 0x2D, 0x36, 0x63, 0x34, 0x62, 0x66, 0x66, 0x36, 0x64, 0x36, 0x31, 0x39, 0x30, 0x2F, 
0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2F, 0x37, 0x31, 0x31, 
0x37, 0x62, 0x35, 0x64, 0x36, 0x2D, 0x65, 0x35, 0x63, 0x62, 0x2D, 0x34, 0x39, 0x30, 0x34, 0x2D, 
0x39, 0x38, 0x37, 0x66, 0x2D, 0x66, 0x37, 0x36, 0x30, 0x35, 0x34, 0x30, 0x64, 0x63, 0x30, 0x64, 
0x30, 0x2F, 0x64, 0x65, 0x72, 0x30, 0x11, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x0A, 0x30, 0x08, 
0x30, 0x06, 0x06, 0x04, 0x55, 0x1D, 0x20, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 
0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x03, 0xA8, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 
0x01, 0xFF, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 
0x30, 0x2D, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x26, 0x30, 0x24, 0x82, 0x22, 0x41, 0x34, 0x35, 
0x38, 0x30, 0x46, 0x39, 0x30, 0x30, 0x30, 0x46, 0x30, 0x2E, 0x69, 0x64, 0x65, 0x6E, 0x74, 0x69, 
0x74, 0x79, 0x2E, 0x70, 0x61, 0x6E, 0x65, 0x6C, 0x2E, 0x6B, 0x73, 0x2E, 0x69, 0x6F, 0x74, 0x30, 
0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 
0x02, 0x20, 0x4A, 0x44, 0xA0, 0x65, 0x11, 0x1B, 0x28, 0xB9, 0x2B, 0x43, 0x1E, 0x20, 0x40, 0x20, 
0xB0, 0x93, 0xF4, 0xB8, 0x89, 0x56, 0x47, 0x8E, 0x9D, 0x80, 0x02, 0xF3, 0x59, 0x68, 0x08, 0x7A, 
0xB6, 0xFE, 0x02, 0x20, 0x48, 0xC7, 0x7D, 0xDF, 0x78, 0x4D, 0x7B, 0x3C, 0xDA, 0xE7, 0xFA, 0x7B, 
0x31, 0xD6, 0xCC, 0xC0, 0xFF, 0x97, 0xBB, 0x45, 0xA5, 0x9C, 0xCE, 0x3D, 0xD5, 0x20, 0x05, 0x47, 
0x96, 0x9B, 0x65, 0xC3, 0x31, 0x00
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

int asn_parser(struct parsing_context_s *parsing_context){


    for (asn1_parsing_table_t *entry = parsing_context->parsing_table; entry->tag != 0; entry++) 
    {
        if(entry->pre_parse_function != NULL) 
        {
            entry->pre_parse_function();
        }

        if (entry->parse_function != NULL)
        {
            //DBG("PARSE tag=0x%02X\n", entry->tag);
            if(entry->parse_function(parsing_context, entry->pDst) < 0){
                return -1;
            }
            // Advance tag_ptr to next field
            // For SEQUENCE and SET, data_ptr points inside the structure, so just move there
            // For other types, data_ptr points to the data, so skip over it
            if (entry->pDst == NULL) 
            {
                parsing_context->tag_ptr = parsing_context->data_ptr;
            }
            else
            {
                // Advance past primitive/constructed but non-container field
                parsing_context->tag_ptr = parsing_context->data_ptr + parsing_context->len;
            }
            //DBG("ADVANCED off=%td\n", (ptrdiff_t)(parsing_context->tag_ptr - parsing_context->buff));
            // After advancing, check if we've reached end of one or more containers and pop them
            while (parsing_context->nest_idx > 0 && parsing_context->tag_ptr >= parsing_context->container_end[parsing_context->nest_idx - 1]) {
                //DBG("LEAVE CONTAINER depth_before=%u end_off=%td\n", parsing_context->nest_idx, (ptrdiff_t)(parsing_context->container_end[parsing_context->nest_idx - 1] - parsing_context->buff));
                parsing_context->nest_idx--;
            }
        }
        if (entry->post_parse_function != NULL) 
        {
            entry->post_parse_function();
        }
    }
    return 0;
}

#define HTTP_RESPONSE_FILENAME "response_body.txt"
#define BOUNDARY_STRING_START "--EST-"
#define SERVERKEYGEN_STRING "server-generated-key"
#define SERVERKEYGEN_STRING_LEN 20
#define CERTSONLY_STRING "certs-only"
#define CERTSONLY_STRING_LEN 10

#define LINE_TERMINATOR "\r\n"

/**
 * Search for a specific string in a file. And set the file position to the byte after the found string.
 */
int find_string_in_file(FILE *file, const char *search_string, size_t search_string_len, uint8_t *tempBuffer, size_t tempBufferLen)
{
    if(!file || !search_string || search_string_len == 0 || !tempBuffer || tempBufferLen == 0 || search_string_len > tempBufferLen)
    {
        return -1;
    }

    int c;
    size_t fileStartSearchPos = ftell(file);
    size_t filePos;
    
    uint8_t firstChar = search_string[0];
    while ((c = fgetc(file)) != EOF)
    {
        if (c == firstChar) 
        {
            // Potential match found, read ahead
            tempBuffer[0] = (uint8_t)c;
            filePos = ftell(file);
            fread(tempBuffer + 1, 1, search_string_len - 1, file);

            if (memcmp(tempBuffer, search_string, search_string_len) == 0) 
            {
                // Match found
                return 0;
            } 
            else 
            {
                // No match, reset file position
                fseek(file, filePos, SEEK_SET);
            }
        } 
    }
    fseek(file, fileStartSearchPos, SEEK_SET);
    return -1;
}

#define MAX(A, B) ((A) > (B) ? (A) : (B))

int find_string_in_line(FILE *file, const char *search_string, size_t search_string_len, uint8_t *tempBuffer, size_t tempBufferLen)
{
    if(!file || !search_string || search_string_len == 0 || !tempBuffer || tempBufferLen == 0 || search_string_len > tempBufferLen)
    {
        return -1;
    }
    int ret = 0;
    int c = 0;
    size_t filePosStartSearch = ftell(file);
    size_t filePosEndLine = 0;
    size_t filePos;

    ret = find_string_in_file(file, LINE_TERMINATOR, strlen(LINE_TERMINATOR), tempBuffer, tempBufferLen);
    if (ret != 0)
    {
        return -1; // Line terminator not found
    }
    filePosEndLine = ftell(file) - strlen(LINE_TERMINATOR);
    // Reset to start of line
    fseek(file, filePosStartSearch, SEEK_SET);
    size_t lineLen = filePosEndLine - filePosStartSearch;

    uint8_t firstChar = search_string[0];
    while (lineLen > search_string_len)
    {
        c = fgetc(file);
        lineLen--;

        if (c == firstChar) 
        {
            // Potential match found, read ahead
            tempBuffer[0] = (uint8_t)c;
            filePos = ftell(file);

            ret = fread(tempBuffer + 1, 1, search_string_len - 1, file);
            lineLen -= ret;
            if (memcmp(tempBuffer, search_string, search_string_len) == 0) 
            {
                // Match found
                return 0;
            } 
            else 
            {
                // No match, reset file position
                fseek(file, filePos, SEEK_SET);
            }
        } 
    }

    fseek(file, filePosStartSearch, SEEK_SET);
    return -1;

}


int check_empty_line(FILE *file)
{
    uint8_t buffer[3] = {0};
    size_t bytesRead = fread(buffer, 1, 2, file);
    if (bytesRead < 2) 
    {
        return -1; // Not enough data
    }

    if (buffer[0] == '\r' && buffer[1] == '\n') 
    {
        return 0; // Empty line
    } 
    else 
    {
        // Not an empty line, reset file position
        fseek(file, -((long)bytesRead), SEEK_CUR);
        return -2;
    }
}

// int read_line(FILE *file, uint8_t *buffer, size_t max_len)
// {
//     // leggo il file fino a incontrare LINE_TERMINATOR o fino a max_len

//     size_t bytesRead = 0;
//     uint8_t c;

//     while (bytesRead < max_len - 1) 
//     {
//         c = fgetc(file);
//         if (c == EOF) 
//         {
//             buffer[bytesRead] = '\0';
//             break;
//         }

//         buffer[bytesRead++] = c;

//         // Check for line terminator
//         if (bytesRead >= 2 && buffer[bytesRead - 2] == '\n' && buffer[bytesRead - 1] == '\r') 
//         {
//             buffer[bytesRead - 2] = '\0'; // Null-terminate the string, removing the line terminator
//             break;
//         }
//     }
//     return bytesRead;
// }

int search_base64_obj(FILE *file, uint8_t *workBuffer, char* search_string_obj, size_t workBufferLen)
{
        int ret = find_string_in_file(file, search_string_obj, strlen(search_string_obj), workBuffer, workBufferLen);
    if (ret != 0) {
        printf("Error: %s not found in file\n", search_string_obj);
        return -1;
    }
    // Skip line terminator
    find_string_in_file(file, LINE_TERMINATOR, strlen(LINE_TERMINATOR), workBuffer, workBufferLen);
    // ora il file potrebbe contenere delle righe "Content..." o delle righe vuote prima del base64
    do
    {
        // cerca nella riga
        ret = find_string_in_line(file, "Content-", strlen("Content-"), workBuffer, workBufferLen);
        // passa alla riga successiva
        if(ret == 0)
        {
            find_string_in_file(file, LINE_TERMINATOR, strlen(LINE_TERMINATOR), workBuffer, workBufferLen);
        }
    } while (ret == 0);
    //find_string_in_file(file, LINE_TERMINATOR, strlen(LINE_TERMINATOR), workBuffer, workBufferLen);


    // se ci sono, salto tutte le righe vuote
    while ((ret = check_empty_line(file)) == 0)
    {
        // continua a saltare righe vuote
    }
    if (ret == -1)
    {
        printf("Error reading file while skipping empty lines\n");
        return -1;
    }
    return 0;
}

int read_decode64_save(FILE *fIn, FILE *fOut, uint8_t *workBuffer, size_t workBufferLen)
{
    size_t bytesRead = 0;
    size_t writeLen = 0;
    while (1)
    {
        bytesRead = fread(workBuffer, 1, workBufferLen, fIn);
        if (bytesRead == 0)
        {
            break; // EOF
        }

        // Check for line terminator in buffer
        writeLen = bytesRead;
        for (size_t i = 0; i < bytesRead - 1u; i++)
        {
            if (workBuffer[i] == '\r' && workBuffer[i + 1] == '\n')
            {
                writeLen = i; // Stop before line terminator
                break;
            }
            // TODO: handle base64 decoding here
        }

        fwrite(workBuffer, 1, writeLen, fOut);

        if (writeLen < bytesRead)
        {
            break; // Found line terminator
        }
    }
    return writeLen;
}

int main() 
{
    uint8_t buffer[1024];

    // keygen
    // read http dump
    FILE *fBody = fopen(HTTP_RESPONSE_FILENAME, "rb");
    if (fBody == NULL) {
        printf("Error opening file: %s\n", HTTP_RESPONSE_FILENAME);
        return -1;
    }

    int ret = search_base64_obj(fBody, buffer, SERVERKEYGEN_STRING, sizeof(buffer));
    if (ret != 0)
    {
        fclose(fBody);
        return -1;
    }

    // ora il file punta all'inizio del base64
    // leggo e scrivo su out fino all'a capo
    
    FILE *out = fopen("serverkeygen_base64.txt", "wb");
    if (out == NULL)
    {
        printf("Error opening output file: serverkeygen_base64.txt\n");
        return -1;
    }

    read_decode64_save(fBody, out, buffer, sizeof(buffer));

    fclose(out);
    fclose(fBody);


    //certonly
    // read http dump
    fBody = fopen(HTTP_RESPONSE_FILENAME, "rb");
    if (fBody == NULL) {
        printf("Error opening file: %s\n", HTTP_RESPONSE_FILENAME);
        return -1;
    }

    ret = search_base64_obj(fBody, buffer, CERTSONLY_STRING, sizeof(buffer));
    if (ret != 0)
    {
        fclose(fBody);
        return -1;
    }

    // ora il file punta all'inizio del base64
    // leggo e scrivo su out fino all'a capo
    
    out = fopen("certonly_base64.txt", "wb");
    if (out == NULL)
    {
        printf("Error opening output file: certonly_base64.txt\n");
        return -1;
    }

    read_decode64_save(fBody, out, buffer, sizeof(buffer));

    fclose(out);
    fclose(fBody);


    return 0;
//-----------------------------------------------
    struct parsing_context_s parsing_context_CMS = { 0 };
    struct parsing_context_s parsing_context_cert_only = { 0 };
    int retCode = 0;

    parsing_context_CMS = init_asn1_parser(pkcs7_CMS_enveloped_parsing_table, pkcs7_raw, sizeof(pkcs7_raw));
    retCode = asn_parser(&parsing_context_CMS);
    if (retCode)
    {
        printf("Error parsing CMS structure\n");
        return retCode;
    }

    
    parsing_context_cert_only = init_asn1_parser(pkcs7_certs_only, pkcs7_certs_only_raw, sizeof(pkcs7_certs_only_raw));
    retCode = asn_parser(&parsing_context_cert_only);
    if (retCode)
    {
        printf("Error parsing certs only structure\n");
        return retCode;
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