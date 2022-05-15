#pragma once
#include <Windows.h>
#include "wnf_structs.hpp"

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateWnfStateName(
    _Out_ PWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_LIFETIME NameLifetime,
    _In_ WNF_DATA_SCOPE DataScope,
    _In_ BOOLEAN PersistData,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_ ULONG MaximumStateSize,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteWnfStateName(
    _In_ PCWNF_STATE_NAME StateName
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUpdateWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_reads_bytes_opt_( Length ) const VOID* Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID* ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ LOGICAL CheckStamp
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ const VOID* ExplicitScope
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID* ExplicitScope,
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _Out_writes_bytes_to_opt_( *BufferSize, *BufferSize ) PVOID Buffer,
    _Inout_ PULONG BufferSize
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryWnfStateNameInformation(
    _In_ PCWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_INFORMATION NameInfoClass,
    _In_opt_ const VOID* ExplicitScope,
    _Out_writes_bytes_( InfoBufferSize ) PVOID InfoBuffer,
    _In_ ULONG InfoBufferSize
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSubscribeWnfStateChange(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ ULONG EventMask,
    _Out_opt_ PULONG64 SubscriptionId
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnsubscribeWnfStateChange(
    _In_ PCWNF_STATE_NAME StateName
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetCompleteWnfStateSubscription(
    _In_opt_ PWNF_STATE_NAME OldDescriptorStateName,
    _In_opt_ ULONG64* OldSubscriptionId,
    _In_opt_ ULONG OldDescriptorEventMask,
    _In_opt_ ULONG OldDescriptorStatus,
    _Out_writes_bytes_( DescriptorSize ) PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    _In_ ULONG DescriptorSize
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetWnfProcessNotificationEvent(
    _In_ HANDLE NotificationEvent
);