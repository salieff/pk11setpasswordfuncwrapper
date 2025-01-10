#ifndef PK111_SLOT_INFO_H
#define PK111_SLOT_INFO_H

#include <stdint.h>


/* PKCS #11 disable reasons */
typedef enum {
    PK11_DIS_NONE = 0,
    PK11_DIS_USER_SELECTED = 1,
    PK11_DIS_COULD_NOT_INIT_TOKEN = 2,
    PK11_DIS_TOKEN_VERIFY_FAILED = 3,
    PK11_DIS_TOKEN_NOT_PRESENT = 4
} PK11DisableReasons;

typedef struct CK_VERSION {
    unsigned char major; /* integer portion of version number */
    unsigned char minor; /* 1/100ths portion of version number */
} CK_VERSION;

typedef struct CK_TOKEN_INFO {
    /* label, manufacturerID, and model have been changed from
     * CK_CHAR to CK_UTF8CHAR for v2.10 */
    unsigned char label[32];          /* blank padded */
    unsigned char manufacturerID[32]; /* blank padded */
    unsigned char model[16];          /* blank padded */
    unsigned char serialNumber[16];       /* blank padded */
    unsigned long int flags;                 /* see below */

    /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
     * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
     * changed from CK_USHORT to CK_ULONG for v2.0 */
    unsigned long int ulMaxSessionCount;    /* max open sessions */
    unsigned long int ulSessionCount;       /* sess. now open */
    unsigned long int ulMaxRwSessionCount;  /* max R/W sessions */
    unsigned long int ulRwSessionCount;     /* R/W sess. now open */
    unsigned long int ulMaxPinLen;          /* in bytes */
    unsigned long int ulMinPinLen;          /* in bytes */
    unsigned long int ulTotalPublicMemory;  /* in bytes */
    unsigned long int ulFreePublicMemory;   /* in bytes */
    unsigned long int ulTotalPrivateMemory; /* in bytes */
    unsigned long int ulFreePrivateMemory;  /* in bytes */

    /* hardwareVersion, firmwareVersion, and time are new for
     * v2.0 */
    CK_VERSION hardwareVersion; /* version of hardware */
    CK_VERSION firmwareVersion; /* version of firmware */
    unsigned char utcTime[16];        /* time */
} CK_TOKEN_INFO;

struct PK11SlotInfoStr {
    /* the PKCS11 function list for this slot */
    void *functionList;
    void *module; /* our parent module */
    /* Boolean to indicate the current state of this slot */
    int needTest;           /* Has this slot been tested for Export complience */
    int isPerm;             /* is this slot a permanment device */
    int isHW;               /* is this slot a hardware device */
    int isInternal;         /* is this slot one of our internal PKCS #11 devices */
    int disabled;           /* is this slot disabled... */
    PK11DisableReasons reason; /* Why this slot is disabled */
    int readOnly;           /* is the token in this slot read-only */
    int needLogin;          /* does the token of the type that needs
                                * authentication (still true even if token is logged
                                * in) */
    int hasRandom;          /* can this token generated random numbers */
    int defRWSession;       /* is the default session RW (we open our default
                                * session rw if the token can only handle one session
                                * at a time. */
    int isThreadSafe;       /* copied from the module */
    /* The actual flags (many of which are distilled into the above PRBools) */
    unsigned long int flags; /* flags from PKCS #11 token Info */
    /* a default session handle to do quick and dirty functions */
    unsigned long int session;
    void *sessionLock; /* lock for this session */
    /* our ID */
    unsigned long int slotID;
    /* persistant flags saved from startup to startup */
    unsigned long defaultFlags;
    /* keep track of who is using us so we don't accidently get freed while
     * still in use */
    int refCount; /* to be in/decremented by atomic calls ONLY! */
    void *freeListLock;
    void *freeSymKeysWithSessionHead;
    void *freeSymKeysHead;
    int keyCount;
    int maxKeyCount;
    /* Password control functions for this slot. many of these are only
     * active if the appropriate flag is on in defaultFlags */
    int askpw;           /* what our password options are */
    int timeout;         /* If we're ask_timeout, what is our timeout time is
                          * seconds */
    int authTransact;    /* allow multiple authentications off one password if
                          * they are all part of the same transaction */
    int64_t authTime;     /* when were we last authenticated */
    int minPassword;     /* smallest legal password */
    int maxPassword;     /* largest legal password */
    uint16_t series;     /* break up the slot info into various groups of
                          * inserted tokens so that keys and certs can be
                          * invalidated */
    uint16_t flagSeries; /* record the last series for the last event
                          * returned for this slot */
    int flagState;    /* record the state of the last event returned for this
                          * slot. */
    uint16_t wrapKey;    /* current wrapping key for SSL master secrets */
    unsigned long int wrapMechanism;
    /* current wrapping mechanism for current wrapKey */
    unsigned long int refKeys[1];      /* array of existing wrapping keys for */
    void *mechanismList; /* list of mechanism supported by this
                                       * token */
    int mechanismCount;
    /* cache the certificates stored on the token of this slot */
    void **cert_array;
    int array_size;
    int cert_count;
    char serial[16];
    /* since these are odd sizes, keep them last. They are odd sizes to
     * allow them to become null terminated strings */
    char slot_name[65];
    char token_name[33];
    int hasRootCerts;
    int hasRootTrust;
    int hasRSAInfo;
    unsigned long int RSAInfoFlags;
    int protectedAuthPath;
    int isActiveCard;
    uint32_t lastLoginCheck;
    unsigned int lastState;
    /* for Stan */
    void *nssToken;
    void *nssTokenLock;
    /* the tokeninfo struct */
    CK_TOKEN_INFO tokenInfo;
    /* fast mechanism lookup */
    char mechanismBits[256];
    void *profileList;
    int profileCount;
};

#endif // PK111_SLOT_INFO_H
