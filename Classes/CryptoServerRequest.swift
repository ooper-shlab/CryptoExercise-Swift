//
//  CryptoServerRequest.swift
//  CryptoExercise
//
//  Translated by OOPer in cooperation with shlab.jp, on 2015/4/18.
//
//
/*

 File: CryptoServerRequest.h
 File: CryptoServerRequest.m
 Abstract: Handles a server networking request, composed of cryptographic
 operations, made by a connected client.

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

@objc(CryptoServerRequestDelegate)
protocol CryptoServerRequestDelegate {
    
    func cryptoServerRequestDidFinish(request: CryptoServerRequest)
    func cryptoServerRequestDidReceiveError(request: CryptoServerRequest)
    
}

@objc(CryptoServerRequest)
class CryptoServerRequest: NSObject, NSStreamDelegate {
    
    var istr: NSInputStream
    var ostr: NSOutputStream
    var peerName: String
    var peerPublicKey: NSData? = nil
    weak var delegate: protocol<CryptoServerRequestDelegate, NSObjectProtocol>?
    
    init(inputStream readStream: NSInputStream,
        outputStream writeStream: NSOutputStream,
        peer peerAddress: String,
        delegate anObject: protocol<CryptoServerRequestDelegate, NSObjectProtocol>) {
            
            self.istr = readStream
            self.ostr = writeStream
            self.peerName = peerAddress
            self.peerPublicKey = nil
            self.delegate = anObject
    }
    
    func runProtocol() {
        
        self.istr.delegate = self
        self.istr.scheduleInRunLoop(NSRunLoop.currentRunLoop(), forMode: NSRunLoopCommonModes)
        self.istr.open()
        self.ostr.delegate = self
        self.ostr.scheduleInRunLoop(NSRunLoop.currentRunLoop(), forMode: NSRunLoopCommonModes)
        self.ostr.open()
    }
    
    func stream(stream: NSStream, handleEvent eventCode: NSStreamEvent) {
        switch eventCode {
        case NSStreamEvent.HasSpaceAvailable:
            if stream === self.ostr {
                if (stream as! NSOutputStream).hasSpaceAvailable && self.peerPublicKey != nil {
                    self.createBlobAndSend()
                }
            }
        case NSStreamEvent.HasBytesAvailable:
            if stream === self.istr {
                
                let publicKey = self.receiveData()
                self.istr.close()
                
                if let key = publicKey {
                    self.peerPublicKey = key
                    if self.ostr.hasSpaceAvailable {
                        self.createBlobAndSend()
                    }
                } else {
                    fatalError("Connected Client sent too large of a key." )
                    //delegate?.cryptoServerRequestDidReceiveError(self)
                }
            }
        case NSStreamEvent.ErrorOccurred:
            // No debugging facility because we don't want to exit even in DEBUG.
            // It's annoying.
            NSLog("stream: %@", stream)
            delegate?.cryptoServerRequestDidReceiveError(self)
        default:
            break
        }
    }
    
    func createBlobAndSend() {
        assert(peerPublicKey != nil)
        var sentBytes: size_t = 0
        let cryptoBlob = self.createBlob(self.peerName, peerPublicKey: self.peerPublicKey!)
        
        if cryptoBlob != nil {
            sentBytes = self.sendData(cryptoBlob)
        } else {
            assert(false, "Something wrong with the building of the crypto blob.\n")
        }
        
        assert(sentBytes == cryptoBlob!.length, "Only sent \(sentBytes) bytes of crypto blob.")
        
        self.ostr.close()
        
        // Remove ourselves from the mutable container and thereby releasing ourselves.
        delegate?.cryptoServerRequestDidFinish(self)
    }
    
    func receiveData() -> NSData? {
        
        var lengthByte: size_t = 0
        var retBlob: NSMutableData? = nil
        
        var len = withUnsafeMutablePointer(&lengthByte) {lengthPtr in
            self.istr.read(UnsafeMutablePointer(lengthPtr), maxLength: sizeof(size_t))
        }
        
        assert(len == sizeof(size_t), "Read failure errno: [\(errno)]")
        
        if lengthByte <= kMaxMessageLength && len == sizeof(size_t) {
            retBlob = NSMutableData(length: lengthByte)
            
            len = self.istr.read(UnsafeMutablePointer(retBlob!.mutableBytes), maxLength: lengthByte)
            
            assert(len == lengthByte, "Read failure, after buffer errno: [\(errno)]")
            
            if len != lengthByte {
                retBlob = nil
            }
        }
        
        return retBlob
    }
    
    func sendData(outData: NSData?) -> size_t {
        var len: size_t = 0
        
        if let data = outData {
            len = data.length
            if len > 0 {
                let longSize = sizeof(size_t)
                
                let message = NSMutableData(capacity: len + longSize)!
                message.appendBytes(&len, length: longSize)
                message.appendData(data)
                
                self.ostr.write(UnsafePointer(message.bytes), maxLength: message.length)
            }
        }
        
        return len
    }
    
    func createBlob(peer: String, peerPublicKey peerKey: NSData) -> NSData? {
        var message: NSData? = nil
        var error: NSError? = nil
        var pad: CCOptions = 0
        
        let messageHolder = NSMutableDictionary()
        let symmetricKey = SecKeyWrapper.sharedWrapper().getSymmetricKeyBytes()
        
        // Build the plain text.
        let plainText = NSData(bytes: kMessageBody, length: count(kMessageBody.utf8) + 1)
        
        // Acquire handle to public key.
        let peerPublicKeyRef = SecKeyWrapper.sharedWrapper().addPeerPublicKey(peer, keyBits: peerKey)
        
        assert(peerPublicKeyRef != nil, "Could not establish client handle to public key.")
        
        if peerPublicKey != nil {
            
            // Add the public key.
            messageHolder[kPubTag] = SecKeyWrapper.sharedWrapper().getPublicKeyBits()
            
            // Add the signature to the message holder.
            messageHolder[kSigTag] = SecKeyWrapper.sharedWrapper().getSignatureBytes(plainText)
            
            // Add the encrypted message.
            messageHolder[kMesTag] = SecKeyWrapper.sharedWrapper().doCipher(plainText, key: symmetricKey!, context: CCOperation(kCCEncrypt), padding: &pad)
            
            // Add the padding PKCS#7 flag.
            messageHolder[kPadTag] = UInt(pad)
            
            // Add the wrapped symmetric key.
            messageHolder[kSymTag] = SecKeyWrapper.sharedWrapper().wrapSymmetricKey(symmetricKey!, keyRef: peerPublicKeyRef!)
            
            message = NSPropertyListSerialization.dataWithPropertyList(messageHolder, format: .BinaryFormat_v1_0, options: 0, error: &error)
            
            // All done. Time to remove the public key from the keychain.
            SecKeyWrapper.sharedWrapper().removePeerPublicKey(peer)
        } else {
            fatalError("Could not establish client handle to public key.")
        }
        
        
        assert(error == nil, error!.localizedDescription)
        
        return message
    }
    
    deinit {
        istr.removeFromRunLoop(NSRunLoop.currentRunLoop(), forMode: NSRunLoopCommonModes)
        
        ostr.removeFromRunLoop(NSRunLoop.currentRunLoop(), forMode: NSRunLoopCommonModes)
        
        
    }
    
}