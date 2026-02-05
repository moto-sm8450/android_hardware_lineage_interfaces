/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#define LOG_TAG "android.hardware.biometrics.fingerprint-service.lineage"

#include <aidl/android/hardware/biometrics/fingerprint/BnSession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprintClientCallback.h>
#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>
#include <android/log.h>
#include <hardware/fingerprint.h>
#include <hardware/hardware.h>
#include <log/log.h>

#include "Legacy2Aidl.h"
#include "LockoutTracker.h"
#include "UdfpsHandler.h"

using ::aidl::android::hardware::biometrics::common::ICancellationSignal;
using ::aidl::android::hardware::biometrics::common::OperationContext;
using ::aidl::android::hardware::biometrics::fingerprint::PointerContext;
using ::aidl::android::hardware::keymaster::HardwareAuthToken;
using ::android::sp;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;

namespace aidl::android::hardware::biometrics::fingerprint {

void onClientDeath(void* cookie);

class Session : public BnSession {
  public:
    Session(UdfpsHandler* udfpsHandler, int userId,
            std::shared_ptr<ISessionCallback> cb, LockoutTracker lockoutTracker);
    ndk::ScopedAStatus generateChallenge() override;
    ndk::ScopedAStatus revokeChallenge(int64_t challenge) override;
    ndk::ScopedAStatus enroll(const HardwareAuthToken& hat,
                              std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus authenticate(int64_t operationId,
                                    std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus detectInteraction(std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus enumerateEnrollments() override;
    ndk::ScopedAStatus removeEnrollments(const std::vector<int32_t>& enrollmentIds) override;
    ndk::ScopedAStatus getAuthenticatorId() override;
    ndk::ScopedAStatus invalidateAuthenticatorId() override;
    ndk::ScopedAStatus resetLockout(const HardwareAuthToken& hat) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus onPointerDown(int32_t pointerId, int32_t x, int32_t y, float minor,
                                     float major) override;
    ndk::ScopedAStatus onPointerUp(int32_t pointerId) override;
    ndk::ScopedAStatus onUiReady() override;
    ndk::ScopedAStatus authenticateWithContext(int64_t operationId, const OperationContext& context,
                                               std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus enrollWithContext(const HardwareAuthToken& hat,
                                         const OperationContext& context,
                                         std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus detectInteractionWithContext(
            const OperationContext& context, std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus onPointerDownWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus onPointerUpWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus onContextChanged(const OperationContext& context) override;
    ndk::ScopedAStatus onPointerCancelWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus setIgnoreDisplayTouches(bool shouldIgnore) override;

    virtual uint64_t preEnrollImpl() { return 0; };
    virtual void postEnrollImpl() {};
    virtual int enrollImpl(const HardwareAuthToken& hat) { return 0; };
    virtual int authenticateImpl(int64_t operationId) { return 0; };
    virtual int enumerateImpl() { return 0; };
    virtual int removeImpl(int32_t fid) { return 0; };
    virtual uint64_t getAuthenticatorIdImpl() { return 0; };
    virtual int cancelImpl() { return 0; };
    virtual void notify(const fingerprint_msg_t* msg) {};

    ndk::ScopedAStatus cancel();
    binder_status_t linkToDeath(AIBinder* binder);
    bool isClosed();

  protected:
    LockoutTracker mLockoutTracker;

    bool checkSensorLockout();

    // The user ID for which this session was created.
    int32_t mUserId;

    // Callback for talking to the framework. This callback must only be called from non-binder
    // threads to prevent nested binder calls and consequently a binder thread exhaustion.
    // Practically, it means that this callback should always be called from the worker thread.
    std::shared_ptr<ISessionCallback> mCb;

    UdfpsHandler* mUdfpsHandler;

  private:
    bool mClosed = false;
    void clearLockout(bool clearAttemptCounter);
    void startLockoutTimer(int64_t timeout);
    void lockoutTimerExpired();

    // lockout timer
    bool mIsLockoutTimerStarted = false;
    bool mIsLockoutTimerAborted = false;

    // Binder death handler.
    AIBinder_DeathRecipient* mDeathRecipient;
};

class SessionHardware : public Session {
  public:
    SessionHardware(fingerprint_device_t* device, UdfpsHandler* udfpsHandler,
                    int userId, std::shared_ptr<ISessionCallback> cb,
                    LockoutTracker lockoutTracker);
    uint64_t preEnrollImpl() override;
    void postEnrollImpl() override;
    int enrollImpl(const HardwareAuthToken& hat) override;
    int authenticateImpl(int64_t operationId) override;
    int enumerateImpl() override;
    int removeImpl(int32_t fid) override;
    uint64_t getAuthenticatorIdImpl() override;
    int cancelImpl() override;
    void notify(const fingerprint_msg_t* msg) override;

  private:
    fingerprint_device_t* mDevice;

    // static ndk::ScopedAStatus ErrorFilter(int32_t error);
    static Error VendorErrorFilter(int32_t error, int32_t* vendorCode);
    static AcquiredInfo VendorAcquiredFilter(int32_t info, int32_t* vendorCode);
};

class SessionHidlCallback;

class SessionHidl : public Session {
  public:
    SessionHidl(IBiometricsFingerprint* service, UdfpsHandler* udfpsHandler, int userId,
                std::shared_ptr<ISessionCallback> cb, LockoutTracker lockoutTracker);
    uint64_t preEnrollImpl() override;
    void postEnrollImpl() override;
    int enrollImpl(const HardwareAuthToken& hat) override;
    int authenticateImpl(int64_t operationId) override;
    int enumerateImpl() override;
    int removeImpl(int32_t fid) override;
    uint64_t getAuthenticatorIdImpl() override;
    int cancelImpl() override;

  private:
    friend SessionHidlCallback;
    IBiometricsFingerprint* mService;
    sp<SessionHidlCallback> mClientCallback;
    int32_t RequestStatusToInt(RequestStatus error);
};

class SessionHidlCallback : public IBiometricsFingerprintClientCallback {
   public:
    SessionHidlCallback(SessionHidl* session,
                        std::shared_ptr<ISessionCallback> cb,
                        LockoutTracker tracker, UdfpsHandler* udfpsHandler)
        : mSession(session), mCb(cb), mLockoutTracker(tracker), mUdfpsHandler(udfpsHandler) {};

    // Methods from
    // ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback
    // follow.
    Return<void> onEnrollResult(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                                uint32_t remaining) override;
    Return<void> onAcquired(uint64_t deviceId, FingerprintAcquiredInfo acquiredInfo,
                            int32_t vendorCode) override;
    Return<void> onAuthenticated(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                                 const hidl_vec<uint8_t>& token) override;
    Return<void> onError(uint64_t deviceId, FingerprintError error, int32_t vendorCode) override;
    Return<void> onRemoved(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                           uint32_t remaining) override;
    Return<void> onEnumerate(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                             uint32_t remaining) override;

   private:
    SessionHidl* mSession;
    std::shared_ptr<ISessionCallback> mCb;
    LockoutTracker mLockoutTracker;
    UdfpsHandler* mUdfpsHandler;

    // static ndk::ScopedAStatus ErrorFilter(int32_t error);
    Error VendorErrorFilter(FingerprintError error, int32_t* vendorCode);
    AcquiredInfo VendorAcquiredFilter(FingerprintAcquiredInfo acquiredInfo);
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
