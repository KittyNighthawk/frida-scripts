/*
 * Title: DetectUIPasteboardObserver
 *
 * Description: This Frida script is used to detect when an application registers an observer for the
 * UIPasteboardChangedNotification notification in NotificationCenter. This notification is often used by applications
 * that want to use the general Pasteboard as a means of transfering data between applications.
 *
 * Created by Kitty Nighthawk 2020
 */

 // Constant values for the ANSI colour codes
 const reset = "\x1b[0m";
 const black = "\u001b[30m";
 const red = "\u001b[31m";
 const green = "\u001b[32m";
 const yellow = "\u001b[33m";
 const blue = "\u001b[34m";
 const magenta = "\u001b[35m";
 const cyan = "\u001b[36m";
 const white = "\u001b[37m";
 const bold = "\u001b[1m";

 console.log(magenta, "[*] Starting Detect UIPasteboard Observers script", reset);

 if(ObjC.available) {
   try {
     const resolver = new ApiResolver('objc');
     const ignoredClasses = [
       "UICompatibilityInputViewController",
       "UINavigationController",
       "UIInputWindowController",
       "UIAlertController",
     ];

     Interceptor.attach(ObjC.classes.UIViewController['- viewDidAppear:'].implementation, {
       onEnter: function(args) {
         const className = ObjC.Object(args[0]).$className;

         if(!(ignoredClasses.indexOf(className) > -1)) {
           var createdObservers = [];
           var removedObservers = [];

           console.log(cyan, "[*] View Controller name:", reset, className);

           resolver.enumerateMatchesSync('*[__NSObserver observerWithCenter:queue:name:object:block:]', {
             onMatch: function(match) {
               createdObservers.push(match);
             },
             onComplete: function() {
               //
             }
           });

           resolver.enumerateMatchesSync('*[__NSObserver forgetObserver:]', {
             onMatch: function(match) {
               removedObservers.push(match);
             },
             onComplete: function() {
               //
             }
           });

           createdObservers.forEach(function(observer) {
             Interceptor.attach(observer.address, {
               onEnter: function (args) {
                 // args[2] = observerWithCenter:
                 // args[3] = queue:
                 // args[4] = name:
                 // args[5] = object:
                 // args[6] = block:
                 const observerName = ObjC.Object(ptr(args[4])).toString();
                 console.log(green, "[+] UIPasteboardChangedNotification observer registered (potential IPC entry point)", reset);
               }
             });
           });

           removedObservers.forEach(function(observer) {
             Interceptor.attach(observer.address, {
               onEnter: function (args) {
                 // args[2] = forgetObserver:
                 const timestamp = new Date();
                 const observerObj = new ObjC.Object(ptr(args[2]));
                 console.log(yellow, "[?] UIPasteboardChangedNotification observer deregistered (interesting)", reset);
               }
             });
           });
         }
       },
     });
   } catch(err) {
     console.log(red, "[!] An exception occured: ", reset, err.message);
   }
 } else {
   console.log(red, "[-] Objective-C runtime is not available.", reset);
 }

 console.log(cyan, "[*] UIPasteboard Observers will now be reported", reset);
