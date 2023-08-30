/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file advapi32.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_ADVAPI32__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_ADVAPI32__

#undef  NAMEOF_API_CREATEPROCESSASUSER

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_CREATEPROCESSASUSER  DECLARE_NAMEOF_API_CREATEPROCESSASUSERA

#define NAMEOF_API_CREATEPROCESSASUSER          NAMEOF_API_CREATEPROCESSASUSERA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_CREATEPROCESSASUSER  DECLARE_NAMEOF_API_CREATEPROCESSASUSERW

#define NAMEOF_API_CREATEPROCESSASUSER          NAMEOF_API_CREATEPROCESSASUSERW
#endif

/* "CreateProcessAsUserA" */
#define DECLARE_NAMEOF_API_CREATEPROCESSASUSERA char NAMEOF_API_CREATEPROCESSASUSERA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 's', 'U', 's', 'e', 'r', 'A', 0, };
/* "CreateProcessAsUserW" */
#define DECLARE_NAMEOF_API_CREATEPROCESSASUSERW char NAMEOF_API_CREATEPROCESSASUSERW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 's', 'U', 's', 'e', 'r', 'W', 0, };

/* @brief
    Creates a new process and its primary thread.
    The new process runs in the security context of the user represented by the specified token.
    Typically, the process that calls the CreateProcessAsUser function must have the SE_INCREASE_QUOTA_NAME privilege and may require the SE_ASSIGNPRIMARYTOKEN_NAME privilege if the token is not assignable.
    If this function fails with ERROR_PRIVILEGE_NOT_HELD (1314), use the CreateProcessWithLogonW function instead.
    CreateProcessWithLogonW requires no special privileges, but the specified user account must be allowed to log on interactively.
    Generally, it is best to use CreateProcessWithLogonW to create a process with alternate credentials.
 */
typedef BOOL (__stdcall* CREATEPROCESSASUSER)(
    HANDLE hToken,
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

/* "CreateProcessWithTokenW" */
#define DECLARE_NAMEOF_API_CREATEPROCESSWITHTOKENW char NAMEOF_API_CREATEPROCESSWITHTOKENW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W', 'i', 't', 'h', 'T', 'o', 'k', 'e', 'n', 'W', 0, };

/* @brief
    Creates a new process and its primary thread.
    The new process runs in the security context of the specified token.
    It can optionally load the user profile for the specified user.
    The process that calls CreateProcessWithTokenW must have the SE_IMPERSONATE_NAME privilege.
    If this function fails with ERROR_PRIVILEGE_NOT_HELD (1314), use the CreateProcessAsUser or CreateProcessWithLogonW function instead.
    Typically, the process that calls CreateProcessAsUser must have the SE_INCREASE_QUOTA_NAME privilege and may require the SE_ASSIGNPRIMARYTOKEN_NAME privilege if the token is not assignable.
    CreateProcessWithLogonW requires no special privileges, but the specified user account must be allowed to log on interactively.
    Generally, it is best to use CreateProcessWithLogonW to create a process with alternate credentials.
 */
typedef BOOL (__stdcall* CREATEPROCESSWITHTOKENW)(
    IN HANDLE hToken,
    IN DWORD dwLogonFlags,
    IN OPTIONAL LPCWSTR lpApplicationName,
    IN OUT OPTIONAL LPWSTR lpCommandLine,
    IN DWORD dwCreationFlags,
    IN OPTIONAL LPVOID lpEnvironment,
    IN OPTIONAL LPCWSTR lpCurrentDirectory,
    IN LPSTARTUPINFOW lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInfo
    );

#undef  NAMEOF_API_LOGONUSER

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_LOGONUSER            DECLARE_NAMEOF_API_LOGONUSERA

#define NAMEOF_API_LOGONUSER                    NAMEOF_API_LOGONUSERA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_LOGONUSER            DECLARE_NAMEOF_API_LOGONUSERW

#define NAMEOF_API_LOGONUSER                    NAMEOF_API_LOGONUSERW
#endif

/* "LogonUserA" */
#define DECLARE_NAMEOF_API_LOGONUSERA char NAMEOF_API_LOGONUSERA[] = { 'L', 'o', 'g', 'o', 'n', 'U', 's', 'e', 'r', 'A', 0, };
/* "LogonUserW" */
#define DECLARE_NAMEOF_API_LOGONUSERW char NAMEOF_API_LOGONUSERW[] = { 'L', 'o', 'g', 'o', 'n', 'U', 's', 'e', 'r', 'W', 0, };

/* @brief
    The LogonUser function attempts to log a user on to the local computer.
    The local computer is the computer from which LogonUser was called.
    You cannot use LogonUser to log on to a remote computer.
    You specify the user with a user name and domain and authenticate the user with a plaintext password.
    If the function succeeds, you receive a handle to a token that represents the logged-on user.
    You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
   @comment
    NT+
 */
typedef BOOL (__stdcall *LOGONUSER)(
    __in LPTSTR lpszUsername,
    __in_opt LPTSTR lpszDomain,
    __in LPTSTR lpszPassword,
    __in DWORD dwLogonType,
    __in DWORD dwLogonProvider,
    __out PHANDLE phToken
    );

/* "CreateProcessWithLogonW" */
#define DECLARE_NAMEOF_API_CREATEPROCESSWITHLOGONW char NAMEOF_API_CREATEPROCESSWITHLOGONW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W', 'i', 't', 'h', 'L', 'o', 'g', 'o', 'n', 'W', 0, };


/* @brief
    Creates a new process and its primary thread.
    Then the new process runs the specified executable file in the security context of the specified credentials (user, domain, and password).
    It can optionally load the user profile for a specified user.
    This function is similar to the CreateProcessAsUser and CreateProcessWithTokenW functions, except that the caller does not need to call the LogonUser function to authenticate the user and get a token.
   @comment
    2000+
 */
typedef BOOL (WINAPI *CREATEPROCESSWITHLOGONW)(
    __in LPCWSTR lpUsername,
    __in_opt LPCWSTR lpDomain,
    __in LPCWSTR lpPassword,
    __in DWORD dwLogonFlags,
    __in_opt LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in DWORD dwCreationFlags,
    __in_opt LPVOID lpEnvironment,
    __in_opt LPCWSTR lpCurrentDirectory,
    __in LPSTARTUPINFOW lpStartupInfo,
    __out LPPROCESS_INFORMATION lpProcessInformation
    );

/* security */

/* "OpenProcessToken" */
#define DECLARE_NAMEOF_API_OPENPROCESSTOKEN char NAMEOF_API_OPENPROCESSTOKEN[] = { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'k', 'e', 'n', 0, };

/* @brief
    The OpenProcessToken function opens the access token associated with a process.
   @comment
    Platform SDK 에는 TOKEN_ALL_ACCESS 에는 TOKEN_ADJUST_SESSIONID 플래그를 포함
    이로 인해 Windows NT 4.0 은 ERROR_ACCESS_DENIED 가 발생할 수 있다.
 */
typedef BOOL (__stdcall* OPENPROCESSTOKEN)(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
    );

/* "OpenThreadToken" */
#define DECLARE_NAMEOF_API_OPENTHREADTOKEN char NAMEOF_API_OPENTHREADTOKEN[] = { 'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'k', 'e', 'n', 0, };

/* @brief
    The OpenThreadToken function opens the access token associated with a thread.
 */
typedef BOOL (__stdcall* OPENTHREADTOKEN)(
    __in HANDLE ThreadHandle,
    __in DWORD DesiredAccess,
    __in BOOL OpenAsSelf,
    __out PHANDLE TokenHandle
    );

/* "GetTokenInformation" */
#define DECLARE_NAMEOF_API_GETTOKENINFORMATION char NAMEOF_API_GETTOKENINFORMATION[] = { 'G', 'e', 't', 'T', 'o', 'k', 'e', 'n', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0, };

/* @brief
    The GetTokenInformation function retrieves a specified type of information about an access token. The calling process must have appropriate access rights to obtain the information.
    To determine if a user is a member of a specific group, use the CheckTokenMembership function.
    To determine group membership for app container tokens, use the CheckTokenMembershipEx function.
 */
typedef BOOL (__stdcall* GETTOKENINFORMATION)(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID TokenInformation,
    DWORD TokenInformationLength,
    PDWORD ReturnLength
    );

#undef  NAMEOF_API_LOOKUPPRIVILEGEVALUE

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUE DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUEA

#define NAMEOF_API_LOOKUPPRIVILEGEVALUE         NAMEOF_API_LOOKUPPRIVILEGEVALUEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUE DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUEW

#define NAMEOF_API_LOOKUPPRIVILEGEVALUE         NAMEOF_API_LOOKUPPRIVILEGEVALUEW
#endif

/* "LookupPrivilegeValueA" */
#define DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUEA char NAMEOF_API_LOOKUPPRIVILEGEVALUEA[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'V', 'a', 'l', 'u', 'e', 'A', 0, };
/* "LookupPrivilegeValueW" */
#define DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUEW char NAMEOF_API_LOOKUPPRIVILEGEVALUEW[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'V', 'a', 'l', 'u', 'e', 'W', 0, };

/* @brief
    The LookupPrivilegeValue function retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name.
 */
typedef BOOL (__stdcall *LOOKUPPRIVILEGEVALUE)(
    LPCTSTR lpSystemName,
    LPCTSTR lpName,
    PLUID lpLuid
    );

/* "AdjustTokenPrivileges" */
#define DECLARE_NAMEOF_API_ADJUSTTOKENPRIVILEGES char NAMEOF_API_ADJUSTTOKENPRIVILEGES[] = { 'A', 'd', 'j', 'u', 's', 't', 'T', 'o', 'k', 'e', 'n', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 's', 0, };

/* @brief
    The AdjustTokenPrivileges function enables or disables privileges in the specified access token.
    Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
 */
typedef BOOL (__stdcall *ADJUSTTOKENPRIVILEGES)(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
    );

/* "InitializeAcl" */
#define DECLARE_NAMEOF_API_INITIALIZEACL char NAMEOF_API_INITIALIZEACL[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'A', 'c', 'l', 0, };

/* @brief
    The InitializeAcl function initializes a new ACL structure.
 */
typedef BOOL (__stdcall* INITIALIZEACL)(
    __out PACL pAcl,
    __in DWORD nAclLength,
    __in DWORD dwAclRevision
    );

/* "IsValidAcl" */
#define DECLARE_NAMEOF_API_ISVALIDACL char NAMEOF_API_ISVALIDACL[] = { 'I', 's', 'V', 'a', 'l', 'i', 'd', 'A', 'c', 'l', 0, };

/* @brief
    The IsValidAcl function validates an access control list (ACL).
 */
typedef BOOL (__stdcall* ISVALIDACL)(
    __in PACL pAcl
    );

/* "AddAccessAllowedAce" */
#define DECLARE_NAMEOF_API_ADDACCESSALLOWEDACE char NAMEOF_API_ADDACCESSALLOWEDACE[] = { 'A', 'd', 'd', 'A', 'c', 'c', 'e', 's', 's', 'A', 'l', 'l', 'o', 'w', 'e', 'd', 'A', 'c', 'e', 0, };

/* @brief
    The AddAccessAllowedAce function adds an access-allowed access control entry (ACE) to an access control list (ACL).
    The access is granted to a specified security identifier (SID).
    To control whether the new ACE can be inherited by child objects, use the AddAccessAllowedAceEx function.
 */
typedef BOOL (__stdcall* ADDACCESSALLOWEDACE)(
    __inout PACL pAcl,
    __in DWORD dwAceRevision,
    __in DWORD AccessMask,
    __in PSID pSid
    );

/* "AddAccessDeniedAce" */
#define DECLARE_NAMEOF_API_ADDACCESSDENIEDACE char NAMEOF_API_ADDACCESSDENIEDACE[] = { 'A', 'd', 'd', 'A', 'c', 'c', 'e', 's', 's', 'D', 'e', 'n', 'i', 'e', 'd', 'A', 'c', 'e', 0, };

/* @brief
    The AddAccessDeniedAce function adds an access-denied access control entry (ACE) to an access control list (ACL).
    The access is denied to a specified security identifier (SID).
    To control whether the new ACE can be inherited by child objects, use the AddAccessDeniedAceEx function.
 */
typedef BOOL (__stdcall* ADDACCESSDENIEDACE)(
    __inout PACL pAcl,
    __in DWORD dwAceRevision,
    __in DWORD AccessMask,
    __in PSID pSid
    );

#undef  NAMEOF_API_LOOKUPACCOUNTSID

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTSID     DECLARE_NAMEOF_API_LOOKUPACCOUNTSIDA

#define NAMEOF_API_LOOKUPACCOUNTSID             NAMEOF_API_LOOKUPACCOUNTSIDA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTSID     DECLARE_NAMEOF_API_LOOKUPACCOUNTSIDW

#define NAMEOF_API_LOOKUPACCOUNTSID             NAMEOF_API_LOOKUPACCOUNTSIDW
#endif

/* "LookupAccountSidA" */
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTSIDA char NAMEOF_API_LOOKUPACCOUNTSIDA[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'A', 'c', 'c', 'o', 'u', 'n', 't', 'S', 'i', 'd', 'A', 0, };
/* "LookupAccountSidW" */
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTSIDW char NAMEOF_API_LOOKUPACCOUNTSIDW[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'A', 'c', 'c', 'o', 'u', 'n', 't', 'S', 'i', 'd', 'W', 0, };

/* @brief
    The LookupAccountSid function accepts a security identifier (SID) as input.
    It retrieves the name of the account for this SID and the name of the first domain on which this SID is found.
 */
typedef BOOL (__stdcall* LOOKUPACCOUNTSID)(
    LPCTSTR lpSystemName,
    PSID lpSid,
    LPTSTR lpName,
    LPDWORD cchName,
    LPTSTR lpReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
    );

/* "CreateWellKnownSid" */
#define DECLARE_NAMEOF_API_CREATEWELLKNOWNSID char NAMEOF_API_CREATEWELLKNOWNSID[] = { 'C', 'r', 'e', 'a', 't', 'e', 'W', 'e', 'l', 'l', 'K', 'n', 'o', 'w', 'n', 'S', 'i', 'd', 0, };

/* @brief
    The CreateWellKnownSid function creates a SID for predefined aliases.
 */
typedef BOOL (__stdcall* CREATEWELLKNOWNSID)(
    __in WELL_KNOWN_SID_TYPE WellKnownSidType,
    __in_opt PSID DomainSid,
    __out_bcount_part_opt (*cbSid, *cbSid) PSID pSid,
    __inout DWORD *cbSid
    );

#undef  NAMEOF_API_LOOKUPACCOUNTNAME

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTNAME    DECLARE_NAMEOF_API_LOOKUPACCOUNTNAMEA

#define NAMEOF_API_LOOKUPACCOUNTNAME            NAMEOF_API_LOOKUPACCOUNTNAMEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTNAME    DECLARE_NAMEOF_API_LOOKUPACCOUNTNAMEW

#define NAMEOF_API_LOOKUPACCOUNTNAME            NAMEOF_API_LOOKUPACCOUNTNAMEW
#endif

/* "LookupAccountNameA" */
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTNAMEA char NAMEOF_API_LOOKUPACCOUNTNAMEA[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'A', 'c', 'c', 'o', 'u', 'n', 't', 'N', 'a', 'm', 'e', 'A', 0, };
/* "LookupAccountNameW" */
#define DECLARE_NAMEOF_API_LOOKUPACCOUNTNAMEW char NAMEOF_API_LOOKUPACCOUNTNAMEW[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'A', 'c', 'c', 'o', 'u', 'n', 't', 'N', 'a', 'm', 'e', 'W', 0, };

/* @brief
    The LookupAccountName function accepts the name of a system and an account as input.
    It retrieves a security identifier (SID) for the account and the name of the domain on which the account was found.
    The LsaLookupNames function can also retrieve computer accounts.
 */
typedef BOOL (__stdcall* LOOKUPACCOUNTNAME)(
    __in_opt LPCTSTR lpSystemName,
    __in LPCTSTR lpAccountName,
    __out_bcount_part_opt (*cbSid, *cbSid) PSID Sid,
    __inout LPDWORD cbSid,
    __out_ecount_part_opt (*cchReferencedDomainName, *cchReferencedDomainName + 1) LPTSTR ReferencedDomainName,
    __inout LPDWORD cchReferencedDomainName,
    __out PSID_NAME_USE peUse
    );

/* "InitializeSecurityDescriptor" */
#define DECLARE_NAMEOF_API_INITIALIZESECURITYDESCRIPTOR char NAMEOF_API_INITIALIZESECURITYDESCRIPTOR[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 0, };

/* @brief
    The InitializeSecurityDescriptor function initializes a new security descriptor.
 */
typedef BOOL (__stdcall* INITIALIZESECURITYDESCRIPTOR)(
    __out PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __in DWORD dwRevision
    );

/* "SetSecurityDescriptorDacl" */
#define DECLARE_NAMEOF_API_SETSECURITYDESCRIPTORDACL char NAMEOF_API_SETSECURITYDESCRIPTORDACL[] = { 'S', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'D', 'a', 'c', 'l', 0, };

/* @brief
    The SetSecurityDescriptorDacl function sets information in a discretionary access control list (DACL).
    If a DACL is already present in the security descriptor, the DACL is replaced.
 */
typedef BOOL (__stdcall* SETSECURITYDESCRIPTORDACL)(
    __inout PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __in BOOL bDaclPresent,
    __in_opt PACL pDacl,
    __in BOOL bDaclDefaulted
    );

/* "SetSecurityDescriptorSacl" */
#define DECLARE_NAMEOF_API_SETSECURITYDESCRIPTORSACL char NAMEOF_API_SETSECURITYDESCRIPTORSACL[] = { 'S', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'S', 'a', 'c', 'l', 0, };

/* @brief
    The SetSecurityDescriptorDacl function sets information in a discretionary access control list (DACL).
    If a DACL is already present in the security descriptor, the DACL is replaced.
 */
typedef BOOL (__stdcall* SETSECURITYDESCRIPTORSACL)(
    __inout PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __in BOOL bSaclPresent,
    __in_opt PACL pSacl,
    __in BOOL bSaclDefaulted
    );

/* "SetSecurityDescriptorOwner" */
#define DECLARE_NAMEOF_API_SETSECURITYDESCRIPTOROWNER char NAMEOF_API_SETSECURITYDESCRIPTOROWNER[] = { 'S', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'O', 'w', 'n', 'e', 'r', 0, };

/* @brief
    The SetSecurityDescriptorOwner function sets the owner information of an absolute-format security descriptor.
    It replaces any owner information already present in the security descriptor.
 */
typedef BOOL (__stdcall* SETSECURITYDESCRIPTOROWNER)(
    __inout PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __in_opt PSID pOwner,
    __in BOOL bOwnerDefaulted
    );

/* "SetSecurityDescriptorGroup" */
#define DECLARE_NAMEOF_API_SETSECURITYDESCRIPTORGROUP char NAMEOF_API_SETSECURITYDESCRIPTORGROUP[] = { 'S', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'G', 'r', 'o', 'u', 'p', 0, };

/* @brief
    The SetSecurityDescriptorGroup function sets the primary group information of an absolute-format security descriptor, replacing any primary group information already present in the security descriptor.
 */
typedef BOOL (__stdcall* SETSECURITYDESCRIPTORGROUP)(
    __inout PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __in_opt PSID pGroup,
    __in BOOL bGroupDefaulted
    );

/* "AllocateAndInitializeSid" */
#define DECLARE_NAMEOF_API_ALLOCATEANDINITIALIZESID char NAMEOF_API_ALLOCATEANDINITIALIZESID[] = { 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'A', 'n', 'd', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'S', 'i', 'd', 0, };

/* @brief
    The AllocateAndInitializeSid function allocates and initializes a security identifier (SID) with up to eight subauthorities.
 */
typedef BOOL (__stdcall *ALLOCATEANDINITIALIZESID)(
    PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
    BYTE nSubAuthorityCount,
    DWORD dwSubAuthority0,
    DWORD dwSubAuthority1,
    DWORD dwSubAuthority2,
    DWORD dwSubAuthority3,
    DWORD dwSubAuthority4,
    DWORD dwSubAuthority5,
    DWORD dwSubAuthority6,
    DWORD dwSubAuthority7,
    PSID* pSid
    );

/* "EqualSid" */
#define DECLARE_NAMEOF_API_EQUALSID char NAMEOF_API_EQUALSID[] = { 'E', 'q', 'u', 'a', 'l', 'S', 'i', 'd', 0, };

/* @brief
    The EqualSid function tests two security identifier (SID) values for equality.
    Two SIDs must match exactly to be considered equal.
 */
typedef BOOL (__stdcall *EQUALSID)(
    PSID pSid1,
    PSID pSid2
    );

/* @brief
    The GetLengthSid function returns the length, in bytes, of a valid security identifier (SID).
 */
typedef DWORD (__stdcall *GETLENGTHSID)(
    PSID pSid
    );

/* "FreeSid" */
#define DECLARE_NAMEOF_API_FREESID char NAMEOF_API_FREESID[] = { 'F', 'r', 'e', 'e', 'S', 'i', 'd', 0, };

/* @brief
    The FreeSid function frees a security identifier (SID) previously allocated by using the AllocateAndInitializeSid function.
 */
typedef PVOID (__stdcall *FREESID)(
    __in PSID pSid
    );

/* "CheckTokenMembership" */
#define DECLARE_NAMEOF_API_CHECKTOKENMEMBERSHIP char NAMEOF_API_CHECKTOKENMEMBERSHIP[] = { 'C', 'h', 'e', 'c', 'k', 'T', 'o', 'k', 'e', 'n', 'M', 'e', 'm', 'b', 'e', 'r', 's', 'h', 'i', 'p', 0, };

/* @brief
    The CheckTokenMembership function determines whether a specified security identifier (SID) is enabled in an access token.
    If you want to determine group membership for app container tokens, you need to use the CheckTokenMembershipEx function.
 */
typedef BOOL (__stdcall *CHECKTOKENMEMBERSHIP)(
    __in_opt HANDLE TokenHandle,
    __in PSID SidToCheck,
    __out PBOOL IsMember
    );

/* "ImpersonateLoggedOnUser" */
#define DECLARE_NAMEOF_API_IMPERSONATELOGGEDONUSER char NAMEOF_API_IMPERSONATELOGGEDONUSER[] = { 'I', 'm', 'p', 'e', 'r', 's', 'o', 'n', 'a', 't', 'e', 'L', 'o', 'g', 'g', 'e', 'd', 'O', 'n', 'U', 's', 'e', 'r', 0, };
/* "RevertToSelf" */
#define DECLARE_NAMEOF_API_REVERTTOSELF char NAMEOF_API_REVERTTOSELF[] = { 'R', 'e', 'v', 'e', 'r', 't', 'T', 'o', 'S', 'e', 'l', 'f', 0, };

/* @brief
    The ImpersonateLoggedOnUser function lets the calling thread impersonate the security context of a logged-on user.
    The user is represented by a token handle.
 */
typedef BOOL (__stdcall *IMPERSONATELOGGEDONUSER)(__in HANDLE hToken);
/* @brief
    The RevertToSelf function terminates the impersonation of a client application.
 */
typedef BOOL (__stdcall *REVERTTOSELF)(void);

/* SCM */

#if _MSC_FULL_VER >= 140050727
#else
#include <winsvc.h>
#endif

#undef  NAMEOF_API_CHANGESERVICECONFIG
#undef  NAMEOF_API_CHANGESERVICECONFIG2
#undef  NAMEOF_API_CREATESERVICE
#undef  NAMEOF_API_ENUMDEPENDENTSERVICES
#undef  NAMEOF_API_OPENSCMANAGER
#undef  NAMEOF_API_OPENSERVICE
#undef  NAMEOF_API_STARTSERVICE

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIG      DECLARE_NAMEOF_API_CHANGESERVICECONFIGA
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIG2     DECLARE_NAMEOF_API_CHANGESERVICECONFIG2A
#define DECLARE_NAMEOF_API_CREATESERVICE            DECLARE_NAMEOF_API_CREATESERVICEA
#define DECLARE_NAMEOF_API_ENUMDEPENDENTSERVICES    DECLARE_NAMEOF_API_ENUMDEPENDENTSERVICESA
#define DECLARE_NAMEOF_API_OPENSCMANAGER            DECLARE_NAMEOF_API_OPENSCMANAGERA
#define DECLARE_NAMEOF_API_OPENSERVICE              DECLARE_NAMEOF_API_OPENSERVICEA
#define DECLARE_NAMEOF_API_QUERYSERVICECONFIG       DECLARE_NAMEOF_API_QUERYSERVICECONFIGA
#define DECLARE_NAMEOF_API_STARTSERVICE             DECLARE_NAMEOF_API_STARTSERVICEA

#define NAMEOF_API_CHANGESERVICECONFIG              NAMEOF_API_CHANGESERVICECONFIGA
#define NAMEOF_API_CHANGESERVICECONFIG2             NAMEOF_API_CHANGESERVICECONFIG2A
#define NAMEOF_API_CREATESERVICE                    NAMEOF_API_CREATESERVICEA
#define NAMEOF_API_ENUMDEPENDENTSERVICES            NAMEOF_API_ENUMDEPENDENTSERVICESA
#define NAMEOF_API_OPENSCMANAGER                    NAMEOF_API_OPENSCMANAGERA
#define NAMEOF_API_OPENSERVICE                      NAMEOF_API_OPENSERVICEA
#define NAMEOF_API_QUERYSERVICECONFIG               NAMEOF_API_QUERYSERVICECONFIGA
#define NAMEOF_API_STARTSERVICE                     NAMEOF_API_STARTSERVICEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIG      DECLARE_NAMEOF_API_CHANGESERVICECONFIGW
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIG2     DECLARE_NAMEOF_API_CHANGESERVICECONFIG2W
#define DECLARE_NAMEOF_API_CREATESERVICE            DECLARE_NAMEOF_API_CREATESERVICEW
#define DECLARE_NAMEOF_API_ENUMDEPENDENTSERVICES    DECLARE_NAMEOF_API_ENUMDEPENDENTSERVICESW
#define DECLARE_NAMEOF_API_OPENSCMANAGER            DECLARE_NAMEOF_API_OPENSCMANAGERW
#define DECLARE_NAMEOF_API_OPENSERVICE              DECLARE_NAMEOF_API_OPENSERVICEW
#define DECLARE_NAMEOF_API_QUERYSERVICECONFIG       DECLARE_NAMEOF_API_QUERYSERVICECONFIGW
#define DECLARE_NAMEOF_API_STARTSERVICE             DECLARE_NAMEOF_API_STARTSERVICEW

#define NAMEOF_API_CHANGESERVICECONFIG              NAMEOF_API_CHANGESERVICECONFIGW
#define NAMEOF_API_CHANGESERVICECONFIG2             NAMEOF_API_CHANGESERVICECONFIG2W
#define NAMEOF_API_CREATESERVICE                    NAMEOF_API_CREATESERVICEW
#define NAMEOF_API_ENUMDEPENDENTSERVICES            NAMEOF_API_ENUMDEPENDENTSERVICESW
#define NAMEOF_API_OPENSCMANAGER                    NAMEOF_API_OPENSCMANAGERW
#define NAMEOF_API_OPENSERVICE                      NAMEOF_API_OPENSERVICEW
#define NAMEOF_API_QUERYSERVICECONFIG               NAMEOF_API_QUERYSERVICECONFIGW
#define NAMEOF_API_STARTSERVICE                     NAMEOF_API_STARTSERVICEW
#endif

/* "ChangeServiceConfigA" */
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIGA char NAMEOF_API_CHANGESERVICECONFIGA[] = { 'C', 'h', 'a', 'n', 'g', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 'o', 'n', 'f', 'i', 'g', 'A', 0, };
/* "ChangeServiceConfigW" */
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIGW char NAMEOF_API_CHANGESERVICECONFIGW[] = { 'C', 'h', 'a', 'n', 'g', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 'o', 'n', 'f', 'i', 'g', 'W', 0, };
/* "ChangeServiceConfig2A" */
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIG2A char NAMEOF_API_CHANGESERVICECONFIG2A[] = { 'C', 'h', 'a', 'n', 'g', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 'o', 'n', 'f', 'i', 'g', '2', 'A', 0, };
/* "ChangeServiceConfig2W" */
#define DECLARE_NAMEOF_API_CHANGESERVICECONFIG2W char NAMEOF_API_CHANGESERVICECONFIG2W[] = { 'C', 'h', 'a', 'n', 'g', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 'o', 'n', 'f', 'i', 'g', '2', 'W', 0, };
/* "CloseServiceHandle" */
#define DECLARE_NAMEOF_API_CLOSESERVICEHANDLE char NAMEOF_API_CLOSESERVICEHANDLE[] = { 'C', 'l', 'o', 's', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0, };
/* "ControlService" */
#define DECLARE_NAMEOF_API_CONTROLSERVICE char NAMEOF_API_CONTROLSERVICE[] = { 'C', 'o', 'n', 't', 'r', 'o', 'l', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 0, };
/* "CreateServiceA" */
#define DECLARE_NAMEOF_API_CREATESERVICEA char NAMEOF_API_CREATESERVICEA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'A', 0, };
/* "CreateServiceW" */
#define DECLARE_NAMEOF_API_CREATESERVICEW char NAMEOF_API_CREATESERVICEW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'W', 0, };
/* "DeleteService" */
#define DECLARE_NAMEOF_API_DELETESERVICE char NAMEOF_API_DELETESERVICE[] = { 'D', 'e', 'l', 'e', 't', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 0, };
/* "EnumDependentServicesA" */
#define DECLARE_NAMEOF_API_ENUMDEPENDENTSERVICESA char NAMEOF_API_ENUMDEPENDENTSERVICESA[] = { 'E', 'n', 'u', 'm', 'D', 'e', 'p', 'e', 'n', 'd', 'e', 'n', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', 'A', 0, };
/* "EnumDependentServicesW" */
#define DECLARE_NAMEOF_API_ENUMDEPENDENTSERVICESW char NAMEOF_API_ENUMDEPENDENTSERVICESW[] = { 'E', 'n', 'u', 'm', 'D', 'e', 'p', 'e', 'n', 'd', 'e', 'n', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', 'W', 0, };
/* "OpenSCManagerA" */
#define DECLARE_NAMEOF_API_OPENSCMANAGERA char NAMEOF_API_OPENSCMANAGERA[] = { 'O', 'p', 'e', 'n', 'S', 'C', 'M', 'a', 'n', 'a', 'g', 'e', 'r', 'A', 0, };
/* "OpenSCManagerW" */
#define DECLARE_NAMEOF_API_OPENSCMANAGERW char NAMEOF_API_OPENSCMANAGERW[] = { 'O', 'p', 'e', 'n', 'S', 'C', 'M', 'a', 'n', 'a', 'g', 'e', 'r', 'W', 0, };
/* "OpenServiceA" */
#define DECLARE_NAMEOF_API_OPENSERVICEA char NAMEOF_API_OPENSERVICEA[] = { 'O', 'p', 'e', 'n', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'A', 0, };
/* "OpenServiceW" */
#define DECLARE_NAMEOF_API_OPENSERVICEW char NAMEOF_API_OPENSERVICEW[] = { 'O', 'p', 'e', 'n', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'W', 0, };
/* "QueryServiceConfigA" */
#define DECLARE_NAMEOF_API_QUERYSERVICECONFIGA char NAMEOF_API_QUERYSERVICECONFIGA[] = { 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 'o', 'n', 'f', 'i', 'g', 'A', 0, };
/* "QueryServiceConfigW" */
#define DECLARE_NAMEOF_API_QUERYSERVICECONFIGW char NAMEOF_API_QUERYSERVICECONFIGW[] = { 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 'o', 'n', 'f', 'i', 'g', 'W', 0, };
/* "QueryServiceStatus" */
#define DECLARE_NAMEOF_API_QUERYSERVICESTATUS char NAMEOF_API_QUERYSERVICESTATUS[] = { 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'S', 't', 'a', 't', 'u', 's', 0, };
/* "StartServiceA" */
#define DECLARE_NAMEOF_API_STARTSERVICEA char NAMEOF_API_STARTSERVICEA[] = { 'S', 't', 'a', 'r', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'A', 0, };
/* "StartServiceW" */
#define DECLARE_NAMEOF_API_STARTSERVICEW char NAMEOF_API_STARTSERVICEW[] = { 'S', 't', 'a', 'r', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'W', 0, };

/* @brief
    Changes the configuration parameters of a service.
    To change the optional configuration parameters, use the ChangeServiceConfig2 function.
 */
typedef BOOL (WINAPI *CHANGESERVICECONFIG)(
    __in SC_HANDLE hService,
    __in DWORD dwServiceType,
    __in DWORD dwStartType,
    __in DWORD dwErrorControl,
    __in_opt LPCTSTR lpBinaryPathName,
    __in_opt LPCTSTR lpLoadOrderGroup,
    __out_opt LPDWORD lpdwTagId,
    __in_opt LPCTSTR lpDependencies,
    __in_opt LPCTSTR lpServiceStartName,
    __in_opt LPCTSTR lpPassword,
    __in_opt LPCTSTR lpDisplayName
    );

/* @brief
    Changes the optional configuration parameters of a service.
 */
typedef BOOL (WINAPI *CHANGESERVICECONFIG2)(
    __in SC_HANDLE hService,
    __in DWORD dwInfoLevel,
    __in LPVOID lpInfo
    );

/* @brief
    Closes a handle to a service control manager or service object.
 */
typedef BOOL (WINAPI *CLOSESERVICEHANDLE)(
    __in SC_HANDLE hSCObject
    );

/* @brief
    Sends a control code to a service.
    To specify additional information when stopping a service, use the ControlServiceEx function.
 */
typedef BOOL (WINAPI *CONTROLSERVICE)(
    __in SC_HANDLE hService,
    __in DWORD dwControl,
    __out LPSERVICE_STATUS lpServiceStatus
    );

/* @brief
    Creates a service object and adds it to the specified service control manager database.
 */
typedef SC_HANDLE (WINAPI *CREATESERVICE)(
    __in SC_HANDLE hSCManager,
    __in LPCTSTR lpServiceName,
    __in LPCTSTR lpDisplayName,
    __in DWORD dwDesiredAccess,
    __in DWORD dwServiceType,
    __in DWORD dwStartType,
    __in DWORD dwErrorControl,
    __in LPCTSTR lpBinaryPathName,
    __in LPCTSTR lpLoadOrderGroup,
    __out LPDWORD lpdwTagId,
    __in LPCTSTR lpDependencies,
    __in LPCTSTR lpServiceStartName,
    __in LPCTSTR lpPassword
    );

/* @brief
    Marks the specified service for deletion from the service control manager database.
 */
typedef BOOL (WINAPI *DELETESERVICE)(
    __in SC_HANDLE hService
    );

/* @brief
    Retrieves the name and status of each service that depends on the specified service; that is, the specified service must be running before the dependent services can run.
 */
typedef BOOL (WINAPI *ENUMDEPENDENTSERVICES)(
    __in SC_HANDLE hService,
    __in DWORD dwServiceState,
    __out LPENUM_SERVICE_STATUS lpServices,
    __in DWORD cbBufSize,
    __out LPDWORD pcbBytesNeeded,
    __out LPDWORD lpServicesReturned
    );

/* @brief
    Establishes a connection to the service control manager on the specified computer and opens the specified service control manager database.
 */
typedef SC_HANDLE (WINAPI *OPENSCMANAGER)(
    __in LPCTSTR lpMachineName,
    __in LPCTSTR lpDatabaseName,
    __in DWORD dwDesiredAccess
    );

/* @brief
    Opens an existing service.
 */
typedef SC_HANDLE (WINAPI *OPENSERVICE)(
    __in SC_HANDLE hSCManager,
    __in LPCTSTR lpServiceName,
    __in DWORD dwDesiredAccess
    );

/* @brief
    Retrieves the configuration parameters of the specified service.
    Optional configuration parameters are available using the QueryServiceConfig2 function.
 */
typedef BOOL (WINAPI* QUERYSERVICECONFIG)(
    __in SC_HANDLE hService,
    __out LPQUERY_SERVICE_CONFIG lpServiceConfig,
    __in DWORD cbBufSize,
    __out LPDWORD pcbBytesNeeded
    );

/* @brief
    Retrieves the current status of the specified service.
    This function has been superseded by the QueryServiceStatusEx function.
    QueryServiceStatusEx returns the same information QueryServiceStatus returns, with the addition of the process identifier and additional information for the service.
 */
typedef BOOL (WINAPI *QUERYSERVICESTATUS)(
    __in SC_HANDLE hService,
    __out LPSERVICE_STATUS lpServiceStatus
    );

/* @brief
    Starts a service.
 */
typedef BOOL (WINAPI *STARTSERVICE)(
    __in SC_HANDLE hService,
    __in DWORD dwNumServiceArgs,
    __in LPCTSTR* lpServiceArgVectors
    );

#undef  NAMEOF_API_REGISTERSERVICECTRLHANDLER
#undef  NAMEOF_API_REGISTERSERVICECTRLHANDLEREX
#undef  NAMEOF_API_STARTSERVICECTRLDISPATCHER

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLER   DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLERA
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLEREX DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLEREXA
#define DECLARE_NAMEOF_API_STARTSERVICECTRLDISPATCHER   DECLARE_NAMEOF_API_STARTSERVICECTRLDISPATCHERA
#define DECLARE_NAMEOF_API_ENUMSERVICESSTATUSEX         DECLARE_NAMEOF_API_ENUMSERVICESSTATUSEXA

#define NAMEOF_API_REGISTERSERVICECTRLHANDLER           NAMEOF_API_REGISTERSERVICECTRLHANDLERA
#define NAMEOF_API_REGISTERSERVICECTRLHANDLEREX         NAMEOF_API_REGISTERSERVICECTRLHANDLEREXA
#define NAMEOF_API_STARTSERVICECTRLDISPATCHER           NAMEOF_API_STARTSERVICECTRLDISPATCHERA
#define NAMEOF_API_ENUMSERVICESSTATUSEX                 NAMEOF_API_ENUMSERVICESSTATUSEXA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLER   DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLERW
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLEREX DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLEREXW
#define DECLARE_NAMEOF_API_STARTSERVICECTRLDISPATCHER   DECLARE_NAMEOF_API_STARTSERVICECTRLDISPATCHERW
#define DECLARE_NAMEOF_API_ENUMSERVICESSTATUSEX         DECLARE_NAMEOF_API_ENUMSERVICESSTATUSEXW

#define NAMEOF_API_REGISTERSERVICECTRLHANDLER           NAMEOF_API_REGISTERSERVICECTRLHANDLERW
#define NAMEOF_API_REGISTERSERVICECTRLHANDLEREX         NAMEOF_API_REGISTERSERVICECTRLHANDLEREXW
#define NAMEOF_API_STARTSERVICECTRLDISPATCHER           NAMEOF_API_STARTSERVICECTRLDISPATCHERW
#define NAMEOF_API_ENUMSERVICESSTATUSEX                 NAMEOF_API_ENUMSERVICESSTATUSEXW
#endif

/* "RegisterServiceCtrlHandlerA" */
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLERA char NAMEOF_API_REGISTERSERVICECTRLHANDLERA[] = { 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 't', 'r', 'l', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 'A', 0, };
/* "RegisterServiceCtrlHandlerW" */
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLERW char NAMEOF_API_REGISTERSERVICECTRLHANDLERW[] = { 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 't', 'r', 'l', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 'W', 0, };
/* "RegisterServiceCtrlHandlerExA" */
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLEREXA char NAMEOF_API_REGISTERSERVICECTRLHANDLEREXA[] = { 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 't', 'r', 'l', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 'E', 'x', 'A', 0, };
/* "RegisterServiceCtrlHandlerExW" */
#define DECLARE_NAMEOF_API_REGISTERSERVICECTRLHANDLEREXW char NAMEOF_API_REGISTERSERVICECTRLHANDLEREXW[] = { 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 't', 'r', 'l', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 'E', 'x', 'W', 0, };
/* "SetServiceStatus" */
#define DECLARE_NAMEOF_API_SETSERVICESTATUS char NAMEOF_API_SETSERVICESTATUS[] = { 'S', 'e', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'S', 't', 'a', 't', 'u', 's', 0, }
/* "StartServiceCtrlDispatcherA" */
#define DECLARE_NAMEOF_API_STARTSERVICECTRLDISPATCHERA char NAMEOF_API_STARTSERVICECTRLDISPATCHERA[] = { 'S', 't', 'a', 'r', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 't', 'r', 'l', 'D', 'i', 's', 'p', 'a', 't', 'c', 'h', 'e', 'r', 'A', 0, };
/* "StartServiceCtrlDispatcherW" */
#define DECLARE_NAMEOF_API_STARTSERVICECTRLDISPATCHERW char NAMEOF_API_STARTSERVICECTRLDISPATCHERW[] = { 'S', 't', 'a', 'r', 't', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'C', 't', 'r', 'l', 'D', 'i', 's', 'p', 'a', 't', 'c', 'h', 'e', 'r', 'W', 0, };
/* "EnumServicesStatusExA" */
#define DECLARE_NAMEOF_API_ENUMSERVICESSTATUSEXA char NAMEOF_API_ENUMSERVICESSTATUSEXA[] = { 'E', 'n', 'u', 'm', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', 'S', 't', 'a', 't', 'u', 's', 'E', 'x', 'A', 0, };
/* "EnumServicesStatusExW" */
#define DECLARE_NAMEOF_API_ENUMSERVICESSTATUSEXW char NAMEOF_API_ENUMSERVICESSTATUSEXW[] = { 'E', 'n', 'u', 'm', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', 'S', 't', 'a', 't', 'u', 's', 'E', 'x', 'W', 0, };

/* @brief
    Registers a function to handle service control requests.
    This function has been superseded by the RegisterServiceCtrlHandlerEx function. A service can use either function, but the new function supports user-defined context data, and the new handler function supports additional extended control codes.
   @comment
    NT+
 */
typedef SERVICE_STATUS_HANDLE (WINAPI *REGISTERSERVICECTRLHANDLER)(
    __in LPCTSTR lpServiceName,
    __in LPHANDLER_FUNCTION lpHandlerProc
    );

/* @brief
    Registers a function to handle extended service control requests.
   @comment
    windows 2000+
 */
typedef SERVICE_STATUS_HANDLE (WINAPI *REGISTERSERVICECTRLHANDLEREX)(
    __in LPCTSTR lpServiceName,
    __in LPHANDLER_FUNCTION_EX lpHandlerProc,
    __in LPVOID lpContext
    );

/* @brief
    Updates the service control manager's status information for the calling service.
   @comment
    NT+
 */
typedef BOOL (WINAPI *SETSERVICESTATUS)(
    __in SERVICE_STATUS_HANDLE hServiceStatus,
    __in LPSERVICE_STATUS lpServiceStatus
    );

/* @brief
    Connects the main thread of a service process to the service control manager, which causes the thread to be the service control dispatcher thread for the calling process.
   @comment
    NT+
 */
typedef BOOL (WINAPI *STARTSERVICECTRLDISPATCHER)(
    __in const SERVICE_TABLE_ENTRY* lpServiceTable
    );

/* @brief
    Connects the main thread of a service process to the service control manager, which causes the thread to be the service control dispatcher thread for the calling process.
 */
typedef BOOL (WINAPI *ENUMSERVICESSTATUSEX)(
    __in SC_HANDLE hSCManager,
    __in SC_ENUM_TYPE InfoLevel,
    __in DWORD dwServiceType,
    __in DWORD dwServiceState,
    __out_opt LPBYTE lpServices,
    __in DWORD cbBufSize,
    __out LPDWORD pcbBytesNeeded,
    __out LPDWORD lpServicesReturned,
    __inout_opt LPDWORD lpResumeHandle,
    __in_opt LPCTSTR pszGroupName
    );

#undef  NAMEOF_API_INITIATESYSTEMSHUTDOWNEX

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_INITIATESYSTEMSHUTDOWNEX DECLARE_NAMEOF_API_INITIATESYSTEMSHUTDOWNEXA

#define NAMEOF_API_INITIATESYSTEMSHUTDOWNEX         NAMEOF_API_INITIATESYSTEMSHUTDOWNEXA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_INITIATESYSTEMSHUTDOWNEX DECLARE_NAMEOF_API_INITIATESYSTEMSHUTDOWNEXW

#define NAMEOF_API_INITIATESYSTEMSHUTDOWNEX         NAMEOF_API_INITIATESYSTEMSHUTDOWNEXW
#endif

/* "InitiateSystemShutdownExA" */
#define DECLARE_NAMEOF_API_INITIATESYSTEMSHUTDOWNEXA char NAMEOF_API_INITIATESYSTEMSHUTDOWNEXA[] = { 'I', 'n', 'i', 't', 'i', 'a', 't', 'e', 'S', 'y', 's', 't', 'e', 'm', 'S', 'h', 'u', 't', 'd', 'o', 'w', 'n', 'E', 'x', 'A', 0, };
/* "InitiateSystemShutdownExW" */
#define DECLARE_NAMEOF_API_INITIATESYSTEMSHUTDOWNEXW char NAMEOF_API_INITIATESYSTEMSHUTDOWNEXW[] = { 'I', 'n', 'i', 't', 'i', 'a', 't', 'e', 'S', 'y', 's', 't', 'e', 'm', 'S', 'h', 'u', 't', 'd', 'o', 'w', 'n', 'E', 'x', 'W', 0, };

/* @brief
    Initiates a shutdown and optional restart of the specified computer.
    To record a reason for the shutdown in the event log, call the InitiateSystemShutdownEx function.
 */
typedef BOOL (__stdcall *INITIATESYSTEMSHUTDOWN)(
    __in LPTSTR lpMachineName,
    __in LPTSTR lpMessage,
    __in DWORD dwTimeout,
    __in BOOL bForceAppsClosed,
    __in BOOL bRebootAfterShutdown
    );

/* @brief
    Initiates a shutdown and optional restart of the specified computer, and optionally records the reason for the shutdown.
 */
typedef BOOL (__stdcall* INITIATESYSTEMSHUTDOWNEX)(
    __in LPTSTR lpMachineName,
    __in LPTSTR lpMessage,
    __in DWORD dwTimeout,
    __in BOOL bForceAppsClosed,
    __in BOOL bRebootAfterShutdown,
    __in DWORD dwReason
    );

/* Crypt */

#include <wincrypt.h>

#undef  NAMEOF_API_CRYPTACQUIRECONTEXT

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_CRYPTACQUIRECONTEXT  DECLARE_NAMEOF_API_CRYPTACQUIRECONTEXTA

#define NAMEOF_API_CRYPTACQUIRECONTEXT          NAMEOF_API_CRYPTACQUIRECONTEXTA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_CRYPTACQUIRECONTEXT  DECLARE_NAMEOF_API_CRYPTACQUIRECONTEXTW

#define NAMEOF_API_CRYPTACQUIRECONTEXT          NAMEOF_API_CRYPTACQUIRECONTEXTW
#endif

/* "CryptAcquireContextA" */
#define DECLARE_NAMEOF_API_CRYPTACQUIRECONTEXTA char NAMEOF_API_CRYPTACQUIRECONTEXTA[] = { 'C', 'r', 'y', 'p', 't', 'A', 'c', 'q', 'u', 'i', 'r', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 'A', 0, };
/* "CryptAcquireContextW" */
#define DECLARE_NAMEOF_API_CRYPTACQUIRECONTEXTW char NAMEOF_API_CRYPTACQUIRECONTEXTW[] = { 'C', 'r', 'y', 'p', 't', 'A', 'c', 'q', 'u', 'i', 'r', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 'W', 0, };
/* "CryptCreateHash" */
#define DECLARE_NAMEOF_API_CRYPTCREATEHASH char NAMEOF_API_CRYPTCREATEHASH[] = { 'C', 'r', 'y', 'p', 't', 'C', 'r', 'e', 'a', 't', 'e', 'H', 'a', 's', 'h', 0, };
/* "CryptHashData" */
#define DECLARE_NAMEOF_API_CRYPTHASHDATA char NAMEOF_API_CRYPTHASHDATA[] = { 'C', 'r', 'y', 'p', 't', 'H', 'a', 's', 'h', 'D', 'a', 't', 'a', 0, };
/* "CryptGetHashParam" */
#define DECLARE_NAMEOF_API_CRYPTGETHASHPARAM char NAMEOF_API_CRYPTGETHASHPARAM[] = { 'C', 'r', 'y', 'p', 't', 'G', 'e', 't', 'H', 'a', 's', 'h', 'P', 'a', 'r', 'a', 'm', 0, };
/* "CryptDestroyHash" */
#define DECLARE_NAMEOF_API_CRYPTDESTROYHASH char NAMEOF_API_CRYPTDESTROYHASH[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y', 'H', 'a', 's', 'h', 0, };
/* "CryptReleaseContext" */
#define DECLARE_NAMEOF_API_CRYPTRELEASECONTEXT char NAMEOF_API_CRYPTRELEASECONTEXT[] = { 'C', 'r', 'y', 'p', 't', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 0, };
/* "CryptGenRandom" */
#define DECLARE_NAMEOF_API_CRYPTGENRANDOM char NAMEOF_API_CRYPTGENRANDOM[] = { 'C', 'r', 'y', 'p', 't', 'G', 'e', 'n', 'R', 'a', 'n', 'd', 'o', 'm', 0, };

/* @brief
    The CryptAcquireContext function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP).
    This returned handle is used in calls to CryptoAPI functions that use the selected CSP.
    This function first attempts to find a CSP with the characteristics described in the dwProvType and pszProvider parameters.
    If the CSP is found, the function attempts to find a key container within the CSP that matches the name specified by the pszContainer parameter.
    To acquire the context and the key container of a private key associated with the public key of a certificate, use CryptAcquireCertificatePrivateKey.
    With the appropriate setting of dwFlags, this function can also create and destroy key containers and can provide access to a CSP with a temporary key container if access to a private key is not required.
 */
typedef BOOL (WINAPI *CRYPTACQUIRECONTEXT)(
    __out HCRYPTPROV* phProv,
    __in LPCTSTR pszContainer,
    __in LPCTSTR pszProvider,
    __in DWORD dwProvType,
    __in DWORD dwFlags
    );
/* @brief
    The CryptCreateHash function initiates the hashing of a stream of data.
    It creates and returns to the calling application a handle to a cryptographic service provider (CSP) hash object.
    This handle is used in subsequent calls to CryptHashData and CryptHashSessionKey to hash session keys and other streams of data.
 */
typedef BOOL (WINAPI *CRYPTCREATEHASH)(
    __in HCRYPTPROV hProv,
    __in ALG_ID Algid,
    __in HCRYPTKEY hKey,
    __in DWORD dwFlags,
    __out HCRYPTHASH* phHash
    );
/* @brief
    The CryptHashData function adds data to a specified hash object.
    This function and CryptHashSessionKey can be called multiple times to compute the hash of long or discontinuous data streams.
    Before calling this function, CryptCreateHash must be called to create a handle of a hash object.
 */
typedef BOOL (WINAPI *CRYPTHASHDATA)(
    __in HCRYPTHASH hHash,
    __in BYTE* pbData,
    __in DWORD dwDataLen,
    __in DWORD dwFlags
    );
/* @brief
    The CryptGetHashParam function retrieves data that governs the operations of a hash object.
    The actual hash value can be retrieved by using this function.
 */
typedef BOOL (WINAPI *CRYPTGETHASHPARAM)(
    __in HCRYPTHASH hHash,
    __in DWORD dwParam,
    __out BYTE* pbData,
    __inout DWORD* pdwDataLen,
    __in DWORD dwFlags
    );
/* @brief
    The CryptDestroyHash function destroys the hash object referenced by the hHash parameter.
    After a hash object has been destroyed, it can no longer be used.
    To help ensure security, we recommend that hash objects be destroyed after they have been used.
 */
typedef BOOL (WINAPI *CRYPTDESTROYHASH)(
    __in HCRYPTHASH hHash
    );
/* @brief
    The CryptReleaseContext function releases the handle of a cryptographic service provider (CSP) and a key container.
    At each call to this function, the reference count on the CSP is reduced by one.
    When the reference count reaches zero, the context is fully released and it can no longer be used by any function in the application.
    An application calls this function after finishing the use of the CSP.
    After this function is called, the released CSP handle is no longer valid.
    This function does not destroy key containers or key pairs.
 */
typedef BOOL (WINAPI *CRYPTRELEASECONTEXT)(
    __in HCRYPTPROV hProv,
    __in DWORD dwFlags
    );

typedef BOOL (WINAPI* CRYPTGENRANDOM)(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);

/* "RegNotifyChangeKeyValue" */
#define DECLARE_NAMEOF_API_REGNOTIFYCHANGEKEYVALUE char NAMEOF_API_REGNOTIFYCHANGEKEYVALUE[] = { 'R', 'e', 'g', 'N', 'o', 't', 'i', 'f', 'y', 'C', 'h', 'a', 'n', 'g', 'e', 'K', 'e', 'y', 'V', 'a', 'l', 'u', 'e', 0, };

/* @brief
    Notifies the caller about changes to the attributes or contents of a specified registry key.
 */
typedef LONG (WINAPI *REGNOTIFYCHANGEKEYVALUE)(
    __in HKEY hKey,
    __in BOOL bWatchSubtree,
    __in DWORD dwNotifyFilter,
    __in_opt HANDLE hEvent,
    __in BOOL fAsynchronous
    );

/* minimum supported - XP, 2003 */
#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_CONVERTSIDTOSTRINGSID    DECLARE_NAMEOF_API_CONVERTSIDTOSTRINGSIDA

#define DECLARE_CONVERTSIDTOSTRINGSID               DECLARE_CONVERTSIDTOSTRINGSIDA

#define NAMEOF_API_CONVERTSIDTOSTRINGSID            NAMEOF_API_CONVERTSIDTOSTRINGSIDA
#define CONVERTSIDTOSTRINGSID                       CONVERTSIDTOSTRINGSIDA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_CONVERTSIDTOSTRINGSID    DECLARE_NAMEOF_API_CONVERTSIDTOSTRINGSIDW

#define DECLARE_CONVERTSIDTOSTRINGSID               DECLARE_CONVERTSIDTOSTRINGSIDW

#define NAMEOF_API_CONVERTSIDTOSTRINGSID            NAMEOF_API_CONVERTSIDTOSTRINGSIDW
#define CONVERTSIDTOSTRINGSID                       CONVERTSIDTOSTRINGSIDW
#endif

/* "ConvertSidToStringSidA" */
#define DECLARE_NAMEOF_API_CONVERTSIDTOSTRINGSIDA char NAMEOF_API_CONVERTSIDTOSTRINGSIDA[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'S', 'i', 'd', 'T', 'o', 'S', 't', 'r', 'i', 'n', 'g', 'S', 'i', 'd', 'A', 0, };
/* "ConvertSidToStringSidW" */
#define DECLARE_NAMEOF_API_CONVERTSIDTOSTRINGSIDW char NAMEOF_API_CONVERTSIDTOSTRINGSIDW[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'S', 'i', 'd', 'T', 'o', 'S', 't', 'r', 'i', 'n', 'g', 'S', 'i', 'd', 'W', 0, };

/* @brief
    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.
    To convert the string-format SID back to a valid, functional SID, call the ConvertStringSidToSid function.
 */
typedef BOOL (WINAPI *CONVERTSIDTOSTRINGSIDA)(
    __in PSID Sid,
    __out LPSTR*  StringSid
    );

typedef BOOL (WINAPI *CONVERTSIDTOSTRINGSIDW)(
    __in PSID Sid,
    __out LPWSTR* StringSid
    );

#endif
