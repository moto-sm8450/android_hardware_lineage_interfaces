/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Session.h"

namespace aidl::android::hardware::biometrics::fingerprint {

SessionHidl::SessionHidl(IBiometricsFingerprint* service, UdfpsHandler* udfpsHandler, int userId,
                         std::shared_ptr<ISessionCallback> cb, LockoutTracker lockoutTracker)
    : Session(udfpsHandler, userId, cb, lockoutTracker), mService(service) {

    mClientCallback = new SessionHidlCallback(this, mCb, mLockoutTracker, mUdfpsHandler);

    auto ret = mService->setNotify(mClientCallback);
    if (!ret) {
        ALOGE("Can't register fingerprint module callback");
    }

    if (mUdfpsHandler) {
        mUdfpsHandler->init(nullptr);
    }

    auto path = std::format("/data/vendor_de/{}/fpdata/", userId);
    mService->setActiveGroup(mUserId, hidl_string(path));
}

uint64_t SessionHidl::preEnrollImpl() {
    return mService->preEnroll();
}

void SessionHidl::postEnrollImpl() {
    mService->postEnroll();
}

int SessionHidl::enrollImpl(const HardwareAuthToken& hat) {
    hidl_array<uint8_t, 69> authToken;
    translate(hat, authToken);
    RequestStatus status = mService->enroll(authToken, mUserId, 60);
    return RequestStatusToInt(status);
}

int SessionHidl::authenticateImpl(int64_t operationId) {
    RequestStatus status = mService->authenticate(operationId, mUserId);
    return RequestStatusToInt(status);
}

int SessionHidl::enumerateImpl() {
    RequestStatus status = mService->enumerate();
    return RequestStatusToInt(status);
}

int SessionHidl::removeImpl(int32_t fid) {
    RequestStatus status = mService->remove(mUserId, fid);
    return RequestStatusToInt(status);
}

uint64_t SessionHidl::getAuthenticatorIdImpl() {
    return mService->getAuthenticatorId();
}

int SessionHidl::cancelImpl() {
    if (mUdfpsHandler) {
        mUdfpsHandler->cancel();
    }
    RequestStatus status = mService->cancel();
    return RequestStatusToInt(status);
}

// Translate values returned by HIDL to AIDL-compliant return values
int32_t SessionHidl::RequestStatusToInt(RequestStatus error) {
    switch (error) {
        case RequestStatus::SYS_OK:
            return 0;
        case RequestStatus::SYS_ENOENT:
            return -2;
        case RequestStatus::SYS_EINTR:
            return -4;
        case RequestStatus::SYS_EIO:
            return -5;
        case RequestStatus::SYS_EAGAIN:
            return -11;
        case RequestStatus::SYS_ENOMEM:
            return -12;
        case RequestStatus::SYS_EACCES:
            return -13;
        case RequestStatus::SYS_EFAULT:
            return -14;
        case RequestStatus::SYS_EBUSY:
            return -16;
        case RequestStatus::SYS_EINVAL:
            return -22;
        case RequestStatus::SYS_ENOSPC:
            return -28;
        case RequestStatus::SYS_ETIMEDOUT:
            return -110;
        default:
            return -1;
    }
}

// Translate from errors returned by HIDL to AIDL-compliant Error
Error SessionHidlCallback::VendorErrorFilter(FingerprintError error, int32_t* vendorCode) {
    switch (error) {
        case FingerprintError::ERROR_HW_UNAVAILABLE:
            return Error::HW_UNAVAILABLE;
        case FingerprintError::ERROR_UNABLE_TO_PROCESS:
            return Error::UNABLE_TO_PROCESS;
        case FingerprintError::ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case FingerprintError::ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case FingerprintError::ERROR_CANCELED:
            return Error::CANCELED;
        case FingerprintError::ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        case FingerprintError::ERROR_LOCKOUT:
            *vendorCode = FINGERPRINT_ERROR_LOCKOUT;
            return Error::VENDOR;
        case FingerprintError::ERROR_VENDOR:
            return Error::VENDOR;
        default:
            ALOGE("Unknown error from fingerprint vendor library: %d", error);
            return Error::UNABLE_TO_PROCESS;
    }
}

// Translate acquired messages returned by HIDL to AIDL-compliant AcquiredInfo
AcquiredInfo SessionHidlCallback::VendorAcquiredFilter(FingerprintAcquiredInfo info) {
    switch (info) {
        case FingerprintAcquiredInfo::ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case FingerprintAcquiredInfo::ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case FingerprintAcquiredInfo::ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case FingerprintAcquiredInfo::ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case FingerprintAcquiredInfo::ACQUIRED_TOO_FAST:
            return AcquiredInfo::TOO_FAST;
        case FingerprintAcquiredInfo::ACQUIRED_VENDOR:
            return AcquiredInfo::VENDOR;
        default:
            ALOGE("Unknown acquired message from fingerprint vendor library: %d", info);
            return AcquiredInfo::UNKNOWN;
    }
}

Return<void> SessionHidlCallback::onEnrollResult(uint64_t deviceId, uint32_t fingerId,
                                                 uint32_t groupId, uint32_t remaining) {
    ALOGD("onEnrollResult(fid=%d, gid=%d, rem=%d)", fingerId, groupId, remaining);
    mCb->onEnrollmentProgress(fingerId, remaining);
    return Void();
}

Return<void> SessionHidlCallback::onAcquired(uint64_t deviceId,
                                             FingerprintAcquiredInfo acquiredInfo,
                                             int32_t vendorCode) {
    AcquiredInfo result = VendorAcquiredFilter(acquiredInfo);
    ALOGD("onAcquired(%hhd, %d)", result, vendorCode);
    if (mUdfpsHandler) {
        mUdfpsHandler->onAcquired(static_cast<int32_t>(result), vendorCode);
    }
    // don't process vendor messages further since frameworks try to disable
    // udfps display mode on vendor acquired messages but our sensors send a
    // vendor message during processing...
    if (result != AcquiredInfo::VENDOR) {
        mCb->onAcquired(result, vendorCode);
    }
    return Void();
}

Return<void> SessionHidlCallback::onAuthenticated(uint64_t deviceId, uint32_t fingerId,
                                                  uint32_t groupId,
                                                  const hidl_vec<uint8_t>& token) {
    ALOGD("onAuthenticated(fid=%d, gid=%d)", fingerId, groupId);
    if (fingerId != 0) {
        hw_auth_token_t* hat = (hw_auth_token_t *) token.data();
        HardwareAuthToken authToken;
        translate(*hat, authToken);
        if (mUdfpsHandler) {
            mUdfpsHandler->onAuthenticationSucceeded();
        }
        mCb->onAuthenticationSucceeded(fingerId, authToken);
        mLockoutTracker.reset(true);
    } else {
        if (mUdfpsHandler) {
            mUdfpsHandler->onAuthenticationFailed();
        }
        mCb->onAuthenticationFailed();
        mLockoutTracker.addFailedAttempt();
        mSession->checkSensorLockout();
    }
    return Void();
}

Return<void> SessionHidlCallback::onError(uint64_t deviceId, FingerprintError error,
                                          int32_t vendorCode) {
    Error result = VendorErrorFilter(error, &vendorCode);
    ALOGD("onError(%hhd, %d)", result, vendorCode);
    if (error != FingerprintError::ERROR_NO_ERROR) {
        mCb->onError(result, vendorCode);
    }
    return Void();
}

Return<void> SessionHidlCallback::onRemoved(uint64_t deviceId, uint32_t fingerId,
                                            uint32_t groupId, uint32_t remaining) {
    ALOGD("onRemove(fid=%d, gid=%d, rem=%d)", fingerId, groupId, remaining);
    std::vector<int> enrollments;
    enrollments.push_back(fingerId);
    mCb->onEnrollmentsRemoved(enrollments);
    return Void();
}

Return<void> SessionHidlCallback::onEnumerate(uint64_t deviceId, uint32_t fingerId,
                                              uint32_t groupId, uint32_t remaining) {
    ALOGD("onEnumerate(fid=%d, gid=%d, rem=%d)", fingerId, groupId, remaining);
    static std::vector<int> enrollments;
    enrollments.push_back(fingerId);
    if (remaining == 0) {
        mCb->onEnrollmentsEnumerated(enrollments);
        enrollments.clear();
    }
    return Void();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
