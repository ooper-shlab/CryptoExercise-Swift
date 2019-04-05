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
import CommonCrypto

@objc(CryptoServerRequestDelegate)
protocol CryptoServerRequestDelegate {
    
    func cryptoServerRequestDidFinish(_ request: CryptoServerRequest)
    func cryptoServerRequestDidReceiveError(_ request: CryptoServerRequest)
    
}

@objc(CryptoServerRequest)
class CryptoServerRequest: NSObject, StreamDelegate {
    
    var istr: InputStream
    var ostr: OutputStream
    var peerName: String
    var peerPublicKey: Data? = nil
    weak var delegate: CryptoServerRequestDelegate?
    
    init(inputStream readStream: InputStream,
        outputStream writeStream: OutputStream,
        peer peerAddress: String,
        delegate anObject: CryptoServerRequestDelegate) {
            
            self.istr = readStream
            self.ostr = writeStream
            self.peerName = peerAddress
            self.peerPublicKey = nil
            self.delegate = anObject
    }
    
    func runProtocol() {
        
        self.istr.delegate = self
        self.istr.schedule(in: .current, forMode: .common)
        self.istr.open()
        self.ostr.delegate = self
        self.ostr.schedule(in: .current, forMode: .common)
        self.ostr.open()
    }
    
    func stream(_ stream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case Stream.Event.hasSpaceAvailable:
            if stream === self.ostr {
                if (stream as! OutputStream).hasSpaceAvailable && self.peerPublicKey != nil {
                    self.createBlobAndSend()
                }
            }
        case Stream.Event.hasBytesAvailable:
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
        case Stream.Event.errorOccurred:
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
        
        assert(sentBytes == cryptoBlob!.count, "Only sent \(sentBytes) bytes of crypto blob.")
        
        self.ostr.close()
        
        // Remove ourselves from the mutable container and thereby releasing ourselves.
        delegate?.cryptoServerRequestDidFinish(self)
    }
    
    func receiveData() -> Data? {
        
        var lengthByte: size_t = 0
        var retBlob: Data? = nil
        
        var len = withUnsafeMutablePointer(to: &lengthByte) {lengthPtr in
            lengthPtr.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<size_t>.size) {
                self.istr.read($0, maxLength: MemoryLayout<size_t>.size)
            }
        }
        
        assert(len == MemoryLayout<size_t>.size, "Read failure errno: [\(errno)]")
        
        if lengthByte <= kMaxMessageLength && len == MemoryLayout<size_t>.size {
            retBlob = Data(count: lengthByte)
            
            len = retBlob!.withUnsafeMutableBytes{mutableBytes in
                let mutablePointer = mutableBytes.bindMemory(to: UInt8.self).baseAddress!
                return self.istr.read(mutablePointer, maxLength: lengthByte)
            }
            
            assert(len == lengthByte, "Read failure, after buffer errno: [\(errno)]")
            
            if len != lengthByte {
                retBlob = nil
            }
        }
        
        return retBlob
    }
    
    func sendData(_ outData: Data?) -> size_t {
        var len: size_t = 0
        
        if let data = outData {
            len = data.count
            if len > 0 {
                let longSize = MemoryLayout<size_t>.size
                
                var message = Data(capacity: len + longSize)
                message.append(Data(bytes: &len, count: longSize))
                message.append(data)
                
                message.withUnsafeBytes{bytes in
                    let pointer = bytes.bindMemory(to: UInt8.self).baseAddress!
                    _ = self.ostr.write(pointer, maxLength: message.count)
                }
            }
        }
        
        return len
    }
    
    func createBlob(_ peer: String, peerPublicKey peerKey: Data) -> Data? {
        var message: Data? = nil
        var error: Error? = nil
        var pad: CCOptions = 0
        
        let messageHolder = NSMutableDictionary()
        let symmetricKey = SecKeyWrapper.shared.getSymmetricKeyBytes()
        
        // Build the plain text.
        let plainText = Data(bytes: kMessageBody, count: kMessageBody.utf8.count + 1)
        
        // Acquire handle to public key.
        let peerPublicKeyRef = SecKeyWrapper.shared.addPeerPublicKey(peer, keyBits: peerKey)
        
        assert(peerPublicKeyRef != nil, "Could not establish client handle to public key.")
        
        if peerPublicKey != nil {
            
            // Add the public key.
            messageHolder[kPubTag] = SecKeyWrapper.shared.getPublicKeyBits()
            
            // Add the signature to the message holder.
            messageHolder[kSigTag] = SecKeyWrapper.shared.getSignatureBytes(plainText)
            
            // Add the encrypted message.
            messageHolder[kMesTag] = SecKeyWrapper.shared.doCipher(plainText, key: symmetricKey!, context: CCOperation(kCCEncrypt), padding: &pad)
            
            // Add the padding PKCS#7 flag.
            messageHolder[kPadTag] = UInt(pad)
            
            // Add the wrapped symmetric key.
            messageHolder[kSymTag] = SecKeyWrapper.shared.wrapSymmetricKey(symmetricKey!, keyRef: peerPublicKeyRef!)
            
            do {
                message = try PropertyListSerialization.data(fromPropertyList: messageHolder, format: .binary, options: 0)
            } catch let error1 as NSError {
                error = error1
                message = nil
            }
            
            // All done. Time to remove the public key from the keychain.
            SecKeyWrapper.shared.removePeerPublicKey(peer)
        } else {
            fatalError("Could not establish client handle to public key.")
        }
        
        
        assert(error == nil, error!.localizedDescription)
        
        return message
    }
    
    deinit {
        istr.remove(from: .current, forMode: .common)
        
        ostr.remove(from: .current, forMode: .common)
        
        
    }
    
}
