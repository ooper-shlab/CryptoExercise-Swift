//
//  CryptoServer.swift
//  CryptoExercise
//
//  Translated by OOPer in cooperation with shlab.jp, on 2015/4/18.
//
//
/*

 File: CryptoServer.h
 File: CryptoServer.m
 Abstract: Contains the bootstrapping server networking operations. It gets
 invoked by the LocalBonjourController class during startup.

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

let kCryptoServerCouldNotBindToIPv4Address = 1
let kCryptoServerCouldNotBindToIPv6Address = 2
let kCryptoServerNoSocketsAvailable = 3
let kCryptoServerCouldNotBindOrEstablishNetService = 4

@objc(CryptoServer)
class CryptoServer: NSObject, CryptoServerRequestDelegate, NSNetServiceDelegate {
    var connectionBag: Set<CryptoServerRequest> = []
    var netService: NSNetService?
    
    private let CryptoServerErrorDomain = "CryptoServerErrorDomain"
    
    override init() {
        super.init()
        var thisError: NSError? = nil
        self.setupServer(&thisError)
        
        assert(thisError == nil, thisError!.localizedDescription)
        
    }
    
    func applicationWillTerminate(application: UIApplication) {
        self.teardown()
    }
    
    func netServiceDidPublish(sender: NSNetService) {
        self.netService = sender
    }
    func netService(sender: NSNetService, didNotPublish errorDict: [NSObject : AnyObject]) {
        fatalError(errorDict.description)
    }
    
    func netService(sender: NSNetService, didAcceptConnectionWithInputStream readStream: NSInputStream, outputStream writeStream: NSOutputStream) {
        //###Taken from Apple's sample code WiTap.
        // Due to a bug <rdar://problem/15626440>, this method is called on some unspecified
        // queue rather than the queue associated with the net service (which in this case
        // is the main queue).  Work around this by bouncing to the main queue.
        NSOperationQueue.mainQueue().addOperationWithBlock {
            //### We cannot get client peer info here?
            var peer: String? = "Generic Peer"
//        CFSocketNativeHandle nativeSocketHandle = *(CFSocketNativeHandle *)data;
//        struct sockaddr_in peerAddress;
//        socklen_t peerLen = sizeof(peerAddress);
//        NSString * peer = nil;
//
//        if (getpeername(nativeSocketHandle, (struct sockaddr *)&peerAddress, (socklen_t *)&peerLen) == 0) {
//                    getpeername(nativeSocketHandle, UnsafeMutablePointer($0), &peerLen)
//                }
//            peer = [NSString stringWithUTF8String:inet_ntoa(peerAddress.sin_addr)];
//		} else {
//			peer = @"Generic Peer";
//		}
            
            CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue)
            CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue)
            self.handleConnection(peer, inputStream: readStream, outputStream: writeStream)
        }
    }
    
    func setupServer(error: NSErrorPointer) {
        
        if self.netService != nil {
            // Calling [self run] more than once should be a NOP.
            return
        } else {
            
            if self.netService == nil {
                self.netService = NSNetService(domain: "local", type: kBonjourServiceType, name: UIDevice.currentDevice().name, port: 0)
                self.netService?.delegate = self
            }
            
            if self.netService == nil {
                if error != nil {error.memory = NSError(domain: CryptoServerErrorDomain, code: kCryptoServerCouldNotBindOrEstablishNetService, userInfo: nil)}
                self.teardown()
                return
            }
        }
    }
    
    func run() {
        var thisError: NSError? = nil
        self.setupServer(&thisError)
        
        assert(thisError == nil, thisError!.localizedDescription)
        
        self.netService!.publishWithOptions(.ListenForConnections)
    }
    
    func handleConnection(peerName: String?, inputStream readStream: NSInputStream, outputStream writeStream: NSOutputStream) {
        
        assert(peerName != nil, "No peer name given for client.")
        
        if let peer = peerName  {
            let newPeer = CryptoServerRequest(inputStream: readStream,
                outputStream: writeStream,
                peer: peer,
                delegate: self)
            
            newPeer.runProtocol()
            self.connectionBag.insert(newPeer)
            
        }
    }
    
    func cryptoServerRequestDidFinish(request: CryptoServerRequest) {
        self.connectionBag.remove(request)
    }
    
    func cryptoServerRequestDidReceiveError(request: CryptoServerRequest) {
        self.connectionBag.remove(request)
    }
    
    func teardown() {
        if self.netService != nil {
            self.netService!.stop()
            self.netService = nil
        }
    }
    
    deinit {
        self.teardown()
    }
    
}