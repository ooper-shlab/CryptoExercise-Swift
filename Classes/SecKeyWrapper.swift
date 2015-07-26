//
//  SecKeyWrapper.swift
//  CryptoExercise
//
//  Translated by OOPer in cooperation with shlab.jp, on 2015/4/6.
//
//
/*

 File: SecKeyWrapper.h
 File: SecKeyWrapper.m
 Abstract: Core cryptographic wrapper class to exercise most of the Security
 APIs on the iPhone OS. Start here if all you are interested in are the
 cryptographic APIs on the iPhone OS.

 Version: 1.2

 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple Inc.
 ("Apple") in consideration of your agreement to the following terms, and your
 use, installation, modification or redistribution of this Apple software
 constitutes acceptance of these terms.  If you do not agree with these terms,
 please do not use, install, modify or redistribute this Apple software.

 In consideration of your agreement to abide by the following terms, and subject
 to these terms, Apple grants you a personal, non-exclusive license, under
 Apple's copyrights in this original Apple software (the "Apple Software"), to
 use, reproduce, modify and redistribute the Apple Software, with or without
 modifications, in source and/or binary forms; provided that if you redistribute
 the Apple Software in its entirety and without modifications, you must retain
 this notice and the following text and disclaimers in all such redistributions
 of the Apple Software.
 Neither the name, trademarks, service marks or logos of Apple Inc. may be used
 to endorse or promote products derived from the Apple Software without specific
 prior written permission from Apple.  Except as expressly stated in this notice,
 no other rights or licenses, express or implied, are granted by Apple herein,
 including but not limited to any patent rights that may be infringed by your
 derivative works or by other works in which the Apple Software may be
 incorporated.

 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 COMBINATION WITH YOUR PRODUCTS.

 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR
 DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF
 CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF
 APPLE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 Copyright (C) 2008-2009 Apple Inc. All Rights Reserved.

 */

import UIKit
import Security

/* Begin global declarations */

// Global constants used for symmetric key algorithm choice and
// chosen digest.

// The chosen symmetric key and digest algorithm chosen for this sample is AES and SHA1.
// The reasoning behind this was due to the fact that the iPhone and iPod touch have
// hardware accelerators for those particular algorithms and therefore are energy efficient.

let kChosenCipherBlockSize = kCCBlockSizeAES128
let kChosenCipherKeySize = kCCKeySizeAES128
let kChosenDigestLength = Int(CC_SHA1_DIGEST_LENGTH)

// Global constants for padding schemes.
let kPKCS1 = 11

let kTypeOfWrapPadding = SecPadding.PKCS1
let kTypeOfSigPadding = SecPadding.PKCS1SHA1

// constants used to find public, private, and symmetric keys.
let kPublicKeyTag = "com.apple.sample.publickey"
let kPrivateKeyTag = "com.apple.sample.privatekey"
let kSymmetricKeyTag = "com.apple.sample.symmetrickey"

@objc(SecKeyWrapper)
class SecKeyWrapper: NSObject {
    private var typeOfSymmetricOpts: CCOptions = 0
    private var publicKeyRef: SecKey? = nil
    private var privateKeyRef: SecKey? = nil
    
    var publicTag: NSData
    var privateTag: NSData
    var symmetricTag: NSData
    var symmetricKeyRef: NSData? = nil
    
    // (See cssmtype.h and cssmapple.h on the Mac OS X SDK.)
    
    private let CSSM_ALGID_NONE: UInt = 0
    private let CSSM_ALGID_VENDOR_DEFINED: UInt = 0x8000_0000
    private let CSSM_ALGID_AES: UInt = 0x8000_0001
    
    private static var __sharedKeyWrapper: SecKeyWrapper = SecKeyWrapper()
    
    /* Begin method definitions */
    
    static func sharedWrapper() -> SecKeyWrapper {
        return __sharedKeyWrapper
    }
    
    private override init() {
        // Tag data to search for keys.
        privateTag = NSData(bytes: kPrivateKeyTag.cStringUsingEncoding(NSUTF8StringEncoding)!, length: kPrivateKeyTag.utf8.count + 1)
        publicTag = NSData(bytes: kPublicKeyTag.cStringUsingEncoding(NSUTF8StringEncoding)!, length: kPrivateKeyTag.utf8.count + 1)
        symmetricTag = NSData(bytes: kSymmetricKeyTag.cStringUsingEncoding(NSUTF8StringEncoding)!, length: kSymmetricKeyTag.utf8.count + 1)
        super.init()
        
    }
    
    func deleteAsymmetricKeys() {
        var sanityCheck = noErr
        
        // Set the public key query dictionary.
        let queryPublicKey: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: publicTag,
            kSecAttrKeyType: kSecAttrKeyTypeRSA]
        
        // Set the private key query dictionary.
        let queryPrivateKey: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: privateTag,
            kSecAttrKeyType: kSecAttrKeyTypeRSA]
        
        // Delete the private key.
        sanityCheck = SecItemDelete(queryPrivateKey)
        assert(sanityCheck == noErr || sanityCheck == errSecItemNotFound, "Error removing private key, OSStatus == \(sanityCheck).")
        
        // Delete the public key.
        sanityCheck = SecItemDelete(queryPublicKey)
        assert(sanityCheck == noErr || sanityCheck == errSecItemNotFound, "Error removing public key, OSStatus == \(sanityCheck).")
        
        publicKeyRef = nil
        privateKeyRef = nil
    }
    
    func deleteSymmetricKey() {
        var sanityCheck = noErr
        
        // Set the symmetric key query dictionary.
        let querySymmetricKey: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: symmetricTag,
            kSecAttrKeyType: CSSM_ALGID_AES]
        
        // Delete the symmetric key.
        sanityCheck = SecItemDelete(querySymmetricKey)
        assert(sanityCheck == noErr || sanityCheck == errSecItemNotFound, "Error removing symmetric key, OSStatus == \(sanityCheck).")
        
    }
    
    func generateKeyPair(keySize: Int) {
        var sanityCheck = noErr
        publicKeyRef = nil
        privateKeyRef = nil
        assert(keySize == 512 || keySize == 1024 || keySize == 2048, "\(keySize) is an invalid and unsupported key size.")
        
        // First delete current keys.
        self.deleteAsymmetricKeys()
        
        // Container dictionaries.
        
        // Set top level dictionary for the keypair.
        var keyPairAttr: [NSObject: AnyObject] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: keySize]
        
        // Set the private key dictionary.
        let privateKeyAttr: [NSObject: AnyObject] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: privateTag]
        // See SecKey.h to set other flag values.
        
        // Set the public key dictionary.
        let publicKeyAttr: [NSObject: AnyObject] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: publicTag]
        // See SecKey.h to set other flag values.
        
        // Set attributes to top level dictionary.
        keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr
        keyPairAttr[kSecPublicKeyAttrs] = publicKeyAttr
        
        // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
        sanityCheck = SecKeyGeneratePair(keyPairAttr, &publicKeyRef, &privateKeyRef)
        assert(sanityCheck == noErr && publicKeyRef != nil && privateKeyRef != nil, "Something really bad went wrong with generating the key pair [\(sanityCheck)].")
        
    }
    
    func generateSymmetricKey() {
        var sanityCheck = noErr
        var symmetricKey: [UInt8] = []
        
        // First delete current symmetric key.
        self.deleteSymmetricKey()
        
        // Container dictionary
        var symmetricKeyAttr: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: symmetricTag,
            kSecAttrKeyType: CSSM_ALGID_AES,
            kSecAttrKeySizeInBits: (kChosenCipherKeySize << 3),
            kSecAttrEffectiveKeySize: (kChosenCipherKeySize << 3),
            kSecAttrCanEncrypt: true,
            kSecAttrCanDecrypt: true,
            kSecAttrCanDerive: false,
            kSecAttrCanSign: false,
            kSecAttrCanVerify: false,
            kSecAttrCanWrap: false,
            kSecAttrCanUnwrap: false]
        
        // Allocate some buffer space. I don't trust calloc.
        //###I do trust Array initializer.
        symmetricKey = Array(count: kChosenCipherKeySize, repeatedValue: 0)
        
        sanityCheck = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, &symmetricKey)
        assert(sanityCheck == noErr, "Problem generating the symmetric key, OSStatus == \(sanityCheck).")
        
        self.symmetricKeyRef = NSData(bytes: symmetricKey, length: kChosenCipherKeySize)
        
        // Add the wrapped key data to the container dictionary.
        symmetricKeyAttr[kSecValueData] = self.symmetricKeyRef
        
        // Add the symmetric key to the keychain.
        sanityCheck = SecItemAdd(symmetricKeyAttr, nil)
        assert(sanityCheck == noErr || sanityCheck == errSecDuplicateItem, "Problem storing the symmetric key in the keychain, OSStatus == \(sanityCheck).")
        
    }
    
    func addPeerPublicKey(peerName: String, keyBits publicKey: NSData) -> SecKey? {
        var sanityCheck = noErr
        var peerKeyRef: AnyObject? = nil
        var persistPeer: AnyObject? = nil
        
        let peerTag = peerName.withCString {peerBytes in
            return NSData(bytes: peerBytes, length: peerName.utf8.count)
        }
        var peerPublicKeyAttr: [NSObject: AnyObject] = [
            
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: peerTag,
            kSecValueData: publicKey,
            kSecReturnPersistentRef: true]
        
        sanityCheck = SecItemAdd(peerPublicKeyAttr as CFDictionary, &persistPeer)
        
        // The nice thing about persistent references is that you can write their value out to disk and
        // then use them later. I don't do that here but it certainly can make sense for other situations
        // where you don't want to have to keep building up dictionaries of attributes to get a reference.
        //
        // Also take a look at SecKeyWrapper's methods (CFTypeRef)getPersistentKeyRefWithKeyRef:(SecKeyRef)key
        // & (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef.
        
        assert(sanityCheck == noErr || sanityCheck == errSecDuplicateItem, "Problem adding the peer public key to the keychain, OSStatus == \(sanityCheck).")
        
        if persistPeer != nil {
            peerKeyRef = self.getKeyRefWithPersistentKeyRef(persistPeer!)
        } else {
            peerPublicKeyAttr.removeValueForKey(kSecValueData)
            peerPublicKeyAttr[kSecReturnRef] = true
            // Let's retry a different way.
            sanityCheck = SecItemCopyMatching(peerPublicKeyAttr, &peerKeyRef)
        }
        
        assert(sanityCheck == noErr && peerKeyRef != nil, "Problem acquiring reference to the public key, OSStatus == \(sanityCheck).")
        
        return peerKeyRef as! SecKey?
    }
    
    func removePeerPublicKey(peerName: String) {
        var sanityCheck = noErr
        
        let peerTag = peerName.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)!
        let peerPublicKeyAttr: [NSObject: AnyObject] = [
            
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: peerTag]
        
        sanityCheck = SecItemDelete(peerPublicKeyAttr)
        
        assert(sanityCheck == noErr || sanityCheck == errSecItemNotFound, "Problem deleting the peer public key to the keychain, OSStatus == \(sanityCheck).")
        
    }
    
    func wrapSymmetricKey(symmetricKey: NSData, keyRef publicKey: SecKey) -> NSData? {
        var sanityCheck = noErr
        
        var cipher: NSData? = nil
        
        // Calculate the buffer sizes.
        var cipherBufferSize = SecKeyGetBlockSize(publicKey)
        let keyBufferSize = symmetricKey.length
        
        if kTypeOfWrapPadding == SecPadding.None {
            assert(keyBufferSize <= cipherBufferSize, "Nonce integer is too large and falls outside multiplicative group.")
        } else {
            assert(keyBufferSize <= (cipherBufferSize - 11), "Nonce integer is too large and falls outside multiplicative group.")
        }
        
        // Allocate some buffer space. I don't trust calloc.
        var cipherBuffer: [UInt8] = Array(count: cipherBufferSize, repeatedValue: 0x0)
        
        // Encrypt using the public key.
        sanityCheck = SecKeyEncrypt(publicKey,
            kTypeOfWrapPadding,
            UnsafePointer(symmetricKey.bytes),
            keyBufferSize,
            &cipherBuffer,
            &cipherBufferSize
        )
        
        assert(sanityCheck == noErr, "Error encrypting, OSStatus == \(sanityCheck).")
        
        // Build up cipher text blob.
        cipher = NSData(bytes: cipherBuffer, length: cipherBufferSize)
        
        return cipher
    }
    
    func unwrapSymmetricKey(wrappedSymmetricKey: NSData) -> NSData? {
        var sanityCheck = noErr
        
        var key: NSData? = nil
        
        let privateKey = self.getPrivateKeyRef()
        assert(privateKey != nil, "No private key found in the keychain.")
        
        // Calculate the buffer sizes.
        let cipherBufferSize = SecKeyGetBlockSize(privateKey!)
        var keyBufferSize = wrappedSymmetricKey.length
        
        assert(keyBufferSize <= cipherBufferSize, "Encrypted nonce is too large and falls outside multiplicative group.")
        
        // Allocate some buffer space. I don't trust calloc.
        //###I do trust Array initializer.
        var keyBuffer: [UInt8] = Array(count: keyBufferSize, repeatedValue: 0x0)
        
        // Decrypt using the private key.
        sanityCheck = SecKeyDecrypt(privateKey!,
            kTypeOfWrapPadding,
            UnsafePointer(wrappedSymmetricKey.bytes),
            cipherBufferSize,
            &keyBuffer,
            &keyBufferSize
        )
        
        assert(sanityCheck == noErr, "Error decrypting, OSStatus == \(sanityCheck).")
        
        // Build up plain text blob.
        key = NSData(bytes: keyBuffer, length: keyBufferSize)
        
        return key
    }
    
    func getHashBytes(plainText: NSData) -> NSData {
        var ctx = CC_SHA1_CTX()
        
        // Malloc a buffer to hold hash.
        var hashBytes: [UInt8] = Array(count: kChosenDigestLength, repeatedValue: 0x0)
        
        // Initialize the context.
        CC_SHA1_Init(&ctx)
        // Perform the hash.
        CC_SHA1_Update(&ctx, plainText.bytes, CC_LONG(plainText.length))
        // Finalize the output.
        CC_SHA1_Final(&hashBytes, &ctx)
        
        // Build up the SHA1 blob.
        let hash = NSData(bytes: hashBytes, length: kChosenDigestLength)
        
        return hash
    }
    
    func getSignatureBytes(plainText: NSData) -> NSData? {
        var sanityCheck = noErr
        var signedHash: NSData? = nil
        
        let privateKey = self.getPrivateKeyRef()
        var signedHashBytesSize = SecKeyGetBlockSize(privateKey!)
        
        // Malloc a buffer to hold signature.
        var signedHashBytes: [UInt8] = Array(count: signedHashBytesSize, repeatedValue: 0x0)
        
        // Sign the SHA1 hash.
        sanityCheck = SecKeyRawSign(privateKey!,
            kTypeOfSigPadding,
            UnsafePointer(self.getHashBytes(plainText).bytes),
            kChosenDigestLength,
            &signedHashBytes,
            &signedHashBytesSize
        )
        
        assert(sanityCheck == noErr, "Problem signing the SHA1 hash, OSStatus == \(sanityCheck).")
        
        // Build up signed SHA1 blob.
        signedHash = NSData(bytes:signedHashBytes, length: signedHashBytesSize)
        
        return signedHash
    }
    
    func verifySignature(plainText: NSData, secKeyRef publicKey: SecKey, signature sig: NSData) -> Bool {
        var sanityCheck = noErr
        
        // Get the size of the assymetric block.
        let signedHashBytesSize = SecKeyGetBlockSize(publicKey)
        
        sanityCheck = SecKeyRawVerify(publicKey,
            kTypeOfSigPadding,
            UnsafePointer(self.getHashBytes(plainText).bytes),
            kChosenDigestLength,
            UnsafePointer(sig.bytes),
            signedHashBytesSize
        )
        
        return (sanityCheck == noErr)
    }
    
    func doCipher(plainText: NSData, key symmetricKey: NSData, context encryptOrDecrypt: CCOperation, padding pkcs7: UnsafeMutablePointer<CCOptions>) -> NSData? {
        var ccStatus = CCCryptorStatus(kCCSuccess)
        // Symmetric crypto reference.
        var thisEncipher: CCCryptorRef = nil
        // Cipher Text container.
        var cipherOrPlainText: NSData? = nil
        // Remaining bytes to be performed on.
        var remainingBytes = 0
        // Number of bytes moved to buffer.
        var movedBytes = 0
        // Placeholder for total written.
        var totalBytesWritten = 0
        
        // Initialization vector; dummy in this case 0's.
        let iv: [UInt8] = Array(count: kChosenCipherBlockSize, repeatedValue: 0x0)
        
        assert(pkcs7 != nil, "CCOptions * pkcs7 cannot be NULL.")
        assert(symmetricKey.length == kChosenCipherKeySize, "Disjoint choices for key size.")
        
        // Length of plainText buffer.
        let plainTextBufferSize = plainText.length
        
        assert(plainTextBufferSize > 0, "Empty plaintext passed in.")
        
        // We don't want to toss padding on if we don't need to
        if encryptOrDecrypt == CCOperation(kCCEncrypt) {
            if pkcs7.memory != CCOptions(kCCOptionECBMode) {
                if (plainTextBufferSize % kChosenCipherBlockSize) == 0 {
                    pkcs7.memory = 0x0000
                } else {
                    pkcs7.memory = CCOptions(kCCOptionPKCS7Padding)
                }
            }
        } else if encryptOrDecrypt != CCOperation(kCCDecrypt) {
            fatalError("Invalid CCOperation parameter [\(pkcs7.memory)] for cipher context.")
        }
        
        // Create and Initialize the crypto reference.
        ccStatus = CCCryptorCreate(encryptOrDecrypt,
            CCAlgorithm(kCCAlgorithmAES128),
            pkcs7.memory,
            symmetricKey.bytes,
            kChosenCipherKeySize,
            iv,
            &thisEncipher
        )
        
        assert(ccStatus == CCCryptorStatus(kCCSuccess), "Problem creating the context, ccStatus == \(ccStatus).")
        
        // Calculate byte block alignment for all calls through to and including final.
        let bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true)
        
        // Allocate buffer.
        var bufferPtr: [UInt8] = Array(count: bufferPtrSize, repeatedValue: 0x0)
        
        // Initialize some necessary book keeping.
        
        var ptr = withUnsafeMutablePointer(&bufferPtr[0]) {$0}
        
        // Set up initial size.
        remainingBytes = bufferPtrSize
        
        // Actually perform the encryption or decryption.
        ccStatus = CCCryptorUpdate(thisEncipher,
            plainText.bytes,
            plainTextBufferSize,
            ptr,
            remainingBytes,
            &movedBytes
        )
        
        assert(ccStatus == CCCryptorStatus(kCCSuccess), "Problem with CCCryptorUpdate, ccStatus == \(ccStatus).")
        
        // Handle book keeping.
        ptr += movedBytes
        remainingBytes -= movedBytes
        totalBytesWritten += movedBytes
        
        // Finalize everything to the output buffer.
        ccStatus = CCCryptorFinal(thisEncipher,
            ptr,
            remainingBytes,
            &movedBytes
        )
        
        totalBytesWritten += movedBytes
        
        if thisEncipher != nil {
            CCCryptorRelease(thisEncipher)
            thisEncipher = nil
        }
        
        assert(ccStatus == CCCryptorStatus(kCCSuccess), "Problem with encipherment ccStatus == \(ccStatus)")
        
        cipherOrPlainText = NSData(bytes: bufferPtr, length: totalBytesWritten)
        
        return cipherOrPlainText
        
        /*
        Or the corresponding one-shot call:
        
        ccStatus = CCCrypt(	encryptOrDecrypt,
        kCCAlgorithmAES128,
        typeOfSymmetricOpts,
        (const void *)[self getSymmetricKeyBytes],
        kChosenCipherKeySize,
        iv,
        (const void *) [plainText bytes],
        plainTextBufferSize,
        (void *)bufferPtr,
        bufferPtrSize,
        &movedBytes
        );
        */
    }
    
    func getPublicKeyRef() -> SecKey? {
        var sanityCheck = noErr
        var publicKeyReference: AnyObject? = nil
        
        if publicKeyRef == nil {
            
            // Set the public key query dictionary.
            let queryPublicKey: [NSObject: AnyObject] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: publicTag,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecReturnRef: true]
            
            // Get the key.
            sanityCheck = SecItemCopyMatching(queryPublicKey, &publicKeyReference)
            
            if sanityCheck != noErr {
                publicKeyReference = nil
            }
            
        } else {
            publicKeyReference = publicKeyRef
        }
        
        return publicKeyReference as! SecKey?
    }
    
    func getPublicKeyBits() -> NSData? {
        var publicKeyBits: AnyObject? = nil
        
        // Set the public key query dictionary.
        let queryPublicKey: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: publicTag,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecReturnData: true]
        
        // Get the key bits.
        let sanityCheck = SecItemCopyMatching(queryPublicKey, &publicKeyBits)
        
        if sanityCheck != noErr {
            publicKeyBits = nil
        }
        
        
        return publicKeyBits as! NSData?
    }
    
    func getPrivateKeyRef() -> SecKey? {
        var privateKeyReference: AnyObject? = nil
        
        if privateKeyRef == nil {
            
            // Set the private key query dictionary.
            let queryPrivateKey: [NSObject: AnyObject] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: privateTag,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecReturnRef: true]
            
            // Get the key.
            let sanityCheck = SecItemCopyMatching(queryPrivateKey, &privateKeyReference)
            
            if sanityCheck != noErr {
                privateKeyReference = nil
            }
            
        } else {
            privateKeyReference = privateKeyRef
        }
        
        return privateKeyReference as! SecKey?
    }
    
    func getSymmetricKeyBytes() -> NSData? {
        var symmetricKeyReturn: AnyObject? = nil
        
        if self.symmetricKeyRef == nil {
            
            // Set the private key query dictionary.
            let querySymmetricKey: [NSObject: AnyObject] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: symmetricTag,
                kSecAttrKeyType: CSSM_ALGID_AES,
                kSecReturnData: true]
            
            // Get the key bits.
            let sanityCheck = SecItemCopyMatching(querySymmetricKey, &symmetricKeyReturn)
            
            if sanityCheck == noErr && symmetricKeyReturn != nil {
                self.symmetricKeyRef = symmetricKeyReturn as! NSData?
            } else {
                self.symmetricKeyRef = nil
            }
            
        } else {
            symmetricKeyReturn = self.symmetricKeyRef
        }
        
        return symmetricKeyReturn as! NSData?
    }
    
    func getPersistentKeyRefWithKeyRef(keyRef: SecKey) -> AnyObject? {
        
        // Set the PersistentKeyRef key query dictionary.
        let queryKey: [NSObject: AnyObject] = [
            kSecValueRef: keyRef,
            kSecReturnPersistentRef: true]
        
        // Get the persistent key reference.
        var persistentRef: AnyObject? = nil
        let _ = SecItemCopyMatching(queryKey, &persistentRef)
        
        return persistentRef
    }
    
    func getKeyRefWithPersistentKeyRef(persistentRef: AnyObject) -> SecKey? {
        var keyRef: AnyObject? = nil
        
        
        // Set the SecKeyRef query dictionary.
        let queryKey: [NSObject: AnyObject] = [
            kSecValuePersistentRef: persistentRef,
            kSecReturnRef: true]
        
        // Get the persistent key reference.
        let _ = SecItemCopyMatching(queryKey, &keyRef)
        
        return keyRef as! SecKey?
    }
    
}