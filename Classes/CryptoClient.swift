//
//  CryptoClient.swift
//  CryptoExercise
//
//  Translated by OOPer in cooperation with shlab.jp, on 2015/4/18.
//
//
/*

 File: CryptoClient.h
 File: CryptoClient.m
 Abstract: Contains the client networking and cryptographic operations. It
 gets invoked by the ServiceController class when the connect button is
 pressed.

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

@objc(CryptoClientDelegate)
protocol CryptoClientDelegate {
    
    func cryptoClientDidCompleteConnection(_ cryptoClient: CryptoClient)
    func cryptoClientDidReceiveError(_ cryptoClient: CryptoClient)
    func cryptoClientWillBeginReceivingData(_ cryptoClient: CryptoClient)
    func cryptoClientDidFinishReceivingData(_ cryptoClient: CryptoClient)
    func cryptoClientWillBeginVerifyingData(_ cryptoClient: CryptoClient)
    func cryptoClientDidFinishVerifyingData(_ cryptoClient: CryptoClient, verified: Bool)
    
}

@objc(CryptoClient)
class CryptoClient: NSObject, StreamDelegate {
    var service: NetService?
    var istr: InputStream? = nil
    var ostr: OutputStream? = nil
    weak var delegate: CryptoClientDelegate?
    var isConnected: Bool = false
    
    init(service serviceInstance: NetService?, delegate anObject: CryptoClientDelegate) {
        self.service = serviceInstance
        self.delegate = anObject
        self.isConnected = false
        super.init()
        self.service?.getInputStream(&istr, outputStream: &ostr)
        
    }
    
    func stream(_ stream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case Stream.Event.openCompleted:
            if self.ostr?.streamStatus == .open && self.istr?.streamStatus == .open && !self.isConnected {
                DispatchQueue.main.async {
                    self.delegate?.cryptoClientDidCompleteConnection(self)
                }
                self.isConnected = true
            }
        case Stream.Event.hasSpaceAvailable:
            if stream === self.ostr {
                if (stream as! OutputStream).hasSpaceAvailable {
                    let publicKey = SecKeyWrapper.shared.getPublicKeyBits()!
                    let retLen = self.sendData(publicKey)
                    assert(retLen == publicKey.count, "Attempt to send public key failed, only sent \(retLen) bytes.")
                    
                    self.ostr!.close()
                }
            }
        case Stream.Event.hasBytesAvailable:
            if stream === self.istr {
                DispatchQueue.main.async {
                    self.delegate?.cryptoClientWillBeginReceivingData(self)
                }
                let theBlob = self.receiveData()
                self.istr?.close()
                DispatchQueue.main.async {
                    self.delegate?.cryptoClientDidFinishReceivingData(self)
                }
                if let blob = theBlob {
                    DispatchQueue.main.async {
                        self.delegate?.cryptoClientWillBeginVerifyingData(self)
                    }
                    let verify = self.verifyBlob(blob)
                    DispatchQueue.main.async {
                        self.delegate?.cryptoClientDidFinishVerifyingData(self, verified: verify)
                    }
                } else {
                    assert(false, "Connected Server sent too large of a blob.")
                    delegate?.cryptoClientDidReceiveError(self)
                }
            }
        case Stream.Event.errorOccurred:
            // No debugging facility because we don't want to exit even in DEBUG.
            // It's annoying.
            NSLog("stream: %@", stream)
            delegate?.cryptoClientDidReceiveError(self)
        default:
            break
        }
    }
    
    func runConnection() {
        
        
        guard let istr = self.istr, let ostr = self.ostr else {
            fatalError("Streams not set up properly.")
        }
        istr.delegate = self
        istr.schedule(in: .current, forMode: .commonModes)
        istr.open()
        ostr.delegate = self
        ostr.schedule(in: .current, forMode: .commonModes)
        ostr.open()
    }
    
    func receiveData() -> Data? {
        var lengthByte: size_t = 0
        var retBlob: Data? = nil
        
        var len = withUnsafeMutablePointer(to: &lengthByte) {lengthBuffer in
            lengthBuffer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<size_t>.size) {
                self.istr?.read($0, maxLength: MemoryLayout<size_t>.size) ?? 0
            }
        }
        
        assert(len == MemoryLayout<size_t>.size, "Read failure errno: [\(errno)]")
        
        if lengthByte <= kMaxMessageLength && len == MemoryLayout<size_t>.size {
            retBlob = Data(count: lengthByte)
            
            len = retBlob!.withUnsafeMutableBytes {mutableBytes in
                self.istr?.read(mutableBytes, maxLength: lengthByte) ?? 0
            }
            
            assert(len == lengthByte, "Read failure, after buffer errno: [\(errno)]")
            
            if len != lengthByte {
                retBlob = nil
            }
        }
        
        return retBlob
    }
    
    func sendData(_ outData: Data?) -> Int {
        var len: size_t = 0
        
        if let data = outData {
            len = data.count
            if len > 0 {
                let longSize = MemoryLayout<size_t>.size
                
                var message = Data(capacity: (len + longSize))
                message.append(Data(bytes: &len, count: longSize))
                message.append(data)
                
                message.withUnsafeBytes {bytes in
                    _ = self.ostr?.write(bytes, maxLength: message.count)
                }
            }
        }
        
        return len
    }
    
    func verifyBlob(_ blob: Data) -> Bool {
        var verified = false
        var pad: CCOptions = 0
        
        let peerName = self.service!.name

        do {
            let message = try PropertyListSerialization.propertyList(from: blob, options: .mutableContainers, format: nil) as! NSDictionary
        
            
            // Get the unwrapped symmetric key.
            let symmetricKey = SecKeyWrapper.shared.unwrapSymmetricKey(message[kSymTag]! as! Data)
            
            // Get the padding PKCS#7 flag.
            pad = message[kPadTag]! as! UInt32
            
            // Get the encrypted message and decrypt.
            let plainText = SecKeyWrapper.shared.doCipher(message[kMesTag]! as! Data,
                key: symmetricKey!,
                context: CCOperation(kCCDecrypt),
                padding: &pad)
            
            // Add peer public key.
            let publicKeyRef = SecKeyWrapper.shared.addPeerPublicKey(peerName,
                keyBits: message[kPubTag]! as! Data)
            
            // Verify the signature.
            verified = SecKeyWrapper.shared.verifySignature(plainText!,
                secKeyRef: publicKeyRef!,
                signature: message[kSigTag]! as! Data)
            
            // Clean up by removing the peer public key.
            SecKeyWrapper.shared.removePeerPublicKey(peerName)
        } catch let error as NSError {
            fatalError(error.localizedDescription)
        }
        
        return verified
    }
    
    deinit {
        istr?.remove(from: .current, forMode: .commonModes)
        
        ostr?.remove(from: .current, forMode: .commonModes)
        
    }
    
}
