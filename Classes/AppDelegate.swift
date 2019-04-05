//
//  AppDelegate.swift
//  CryptoExercise
//
//  Translated by OOPer in cooperation with shlab.jp, on 2015/4/18.
//
//
/*

 File: AppDelegate.h
 File: AppDelegate.m
 Abstract: Main controller that houses the operation queue and
 initializes the LocalBonjour Controller.

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
import SystemConfiguration

@UIApplicationMain
@objc(AppDelegate)
class AppDelegate: UIResponder, UIApplicationDelegate {
    @IBOutlet var window: UIWindow?
    @IBOutlet var navController: UINavigationController!
    var cryptoQueue: OperationQueue!
    
    
    func isNetworkAvailableFlags(_ outFlags: UnsafeMutablePointer<SCNetworkReachabilityFlags>?) -> Bool {
        var zeroAddress = sockaddr_in()
        
        zeroAddress.sin_len = UInt8(MemoryLayout.stride(ofValue: zeroAddress))
        zeroAddress.sin_family = sa_family_t(AF_INET)
        
        guard let defaultRouteReachability = withUnsafePointer(to: &zeroAddress, {addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                SCNetworkReachabilityCreateWithAddress(nil, $0)
            }
        }) else {
           return false
        }
        
        var flags: SCNetworkReachabilityFlags = []
        guard SCNetworkReachabilityGetFlags(defaultRouteReachability, &flags) else {
            return false
        }
        
        // kSCNetworkReachabilityFlagsReachable indicates that the specified nodename or address can
        // be reached using the current network configuration.
        let isReachable = flags.contains(.reachable)
        
        // This flag indicates that the specified nodename or address can
        // be reached using the current network configuration, but a
        // connection must first be established.
        //
        // If the flag is false, we don't have a connection. But because CFNetwork
        // automatically attempts to bring up a WWAN connection, if the WWAN reachability
        // flag is present, a connection is not required.
        var noConnectionRequired = !flags.contains(.connectionRequired)
        if flags.contains(.isWWAN) {
            noConnectionRequired = true
        }
        
        // Callers of this method might want to use the reachability flags, so if an 'out' parameter
        // was passed in, assign the reachability flags to it.
        if outFlags != nil {
            outFlags?.pointee = flags
        }
        
        return isReachable && noConnectionRequired
    }
    
    func applicationDidFinishLaunching(_ application: UIApplication) {
        // Is WiFi network available? That's necessary to use Bonjour.
        if !self.isNetworkAvailableFlags(nil) {
            let alertController = UIAlertController(title: "No WiFi network available.",
                                                    message: "Exit this app and enable WiFi using the Settings application.",
                                                    preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
            self.window?.rootViewController?.present(alertController, animated: true, completion: nil)
        } else {
            // Add the controller's view as a subview of the window
            self.window?.addSubview(navController.view)
            
            let theQueue = OperationQueue()
            self.cryptoQueue = theQueue
        }
    }
    
    
}
