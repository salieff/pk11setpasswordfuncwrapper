/*
 * gcc -Wall -fPIC -shared -o libpk11setpasswordfuncwrapper.so pk11setpasswordfuncwrapper.c -ldl
 *
 * And add to /opt/google/chrome/google-chrome, before execs at the end of script:
 * export PK11_HARDCODED_KL_PASSWORD='MyTokenSecurePin'
 * export LD_PRELOAD="/path/to/libpk11setpasswordfuncwrapper.so"
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include <string>
#include <algorithm>

#include "pk11slotinfo.h"


using PK11PasswordFuncType = char *(*)(PK11SlotInfoStr *slot, int retry, void *arg);
using PlStrdupFuncType = char *(*)(const char *s);
using PK11SetPasswordFuncType = void (*)(PK11PasswordFuncType func);

/* Function pointers to hold the value of the glibc functions */
static PlStrdupFuncType real_PL_strdup = NULL;
static PK11SetPasswordFuncType real_PK11_SetPasswordFunc = NULL;
static PK11PasswordFuncType real_PK11PasswordFunc = NULL;

static char * MyPK11PasswordFunc(PK11SlotInfoStr *slot, int retry, void *arg)
{
    printf("[%d] Called MyPK11PasswordFunc(%p, %d, %p)\n", getpid(), slot, retry, arg);

    std::string slotSerial(slot->serial, 16);
    slotSerial.erase(slotSerial.find_last_not_of(" \t\r\n"));
    printf("[%d] Serial = [%s]\n", getpid(), slotSerial.c_str());

    char *serialPassword = getenv(("PK11_HARDCODED_" + slotSerial + "_PASSWORD").c_str());
    char *wrappedPassword = getenv("PK11_HARDCODED_KL_PASSWORD");
    char *effectivePassword = serialPassword ? serialPassword : wrappedPassword;

    // printf("[%d] Serial = [%s] serialPassword = [%s] wrappedPassword = [%s] effectivePassword = [%s] \n", getpid(), slotSerial.c_str(), serialPassword, wrappedPassword, effectivePassword);

    if (effectivePassword != NULL && retry == 0)
    {
        if (real_PL_strdup == NULL)
            real_PL_strdup = reinterpret_cast<PlStrdupFuncType>(dlsym(RTLD_NEXT, "PL_strdup"));

        return real_PL_strdup(effectivePassword);
    }

    if (real_PK11PasswordFunc != NULL)
        return real_PK11PasswordFunc(slot, retry, arg);

    return NULL;
}

/* wrapping function call */
extern "C" void PK11_SetPasswordFunc(PK11PasswordFuncType func)
{
    printf("[%d] Called PK11_SetPasswordFunc(%p)\n", getpid(), func);

    if (real_PK11_SetPasswordFunc == NULL)
        real_PK11_SetPasswordFunc = reinterpret_cast<PK11SetPasswordFuncType>(dlsym(RTLD_NEXT, "PK11_SetPasswordFunc"));

    if (func != NULL && real_PK11PasswordFunc != NULL)
        printf("[%d] ERRROR! real_PK11PasswordFunc already registered!\n", getpid());

    real_PK11PasswordFunc = func;
    real_PK11_SetPasswordFunc(MyPK11PasswordFunc);
}
