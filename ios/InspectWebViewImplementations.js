/*
 * Title: InspectWebViewImplementations
 *
 * Description: This Frida script will hook into any implementations of WebViews (UIWebView or WKWebView) and print
 their properties to the console, highlighting any that are insecure/may present vulnerabilities
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

 console.log(magenta, "[*] Starting WebView inspector script", reset);

 if(ObjC.available) {
   try {
     var resolver = new ApiResolver('objc');
     var className = "";
     var uiWebViewObjectPtrs = [];
     var wkWebViewObjectPtrs = [];
     var uiWebViewlastAccessedURL = "";
     var wkAccessFilesFromFileURLs = false;

     // This hook handles detecting WebView views as they appear in the currently displayed window
     Interceptor.attach(ObjC.classes.UIViewController['- viewDidAppear:'].implementation, {
       onEnter: function(args) {
         // Get the ViewController name
         className = new ObjC.Object(args[0]).$className;
         if(className != "UINavigationController" && className != "UICompatibilityInputViewController" && className != "UIAlertController") {
           console.log("\nView Controller Name: ", cyan, className, reset);
         }

         // Now, get the views details
         var keyWindowDesc = ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();
         // Find any instances of WKWebView and UIWebView, grab the first argument (the pointer to the object in memory)
         var uiRegexp = /^.*<(UIWebView|WKWebView):\s(0x[0-9a-f]*)/gm;
         var regexpMatch = uiRegexp.exec(keyWindowDesc);
         // GROUP 0: Whole matching line
         // GROUP 1: UIWebView || WKWebView
         // GROUP 2: POINTER

         uiWebViewObjectPtrs = [];
         wkWebViewObjectPtrs = [];

         while(regexpMatch != null) {
           if(regexpMatch[1] == "UIWebView") {
             uiWebViewObjectPtrs.push(regexpMatch[2]);
           } else if(regexpMatch[1] == "WKWebView") {
             wkWebViewObjectPtrs.push(regexpMatch[2]);
           } else {
             console.log("[DEBUG] Non-standard webview?");
           }
           // Multiline string being parsed, so get the next line and continue until there are no more lines (null)
           regexpMatch = uiRegexp.exec(keyWindowDesc);
         }

         // Now, use those matches to hook UIWebView load commands to find out what the URL requested is
         // Needs to be done on initial entry or we may miss the load command
         if(uiWebViewObjectPtrs.length > 0) {
           uiWebViewObjectPtrs.forEach(function(webviewPtr) {
             var webview = new ObjC.Object(ptr(webviewPtr));
             var NSURLRequest = new ObjC.Object(ptr(webview.request()));
             var url = NSURLRequest.URL();
             uiWebViewlastAccessedURL = url;
           });
         }
       },
       onLeave: function() {
         if(className != "UINavigationController" && className != "UICompatibilityInputViewController") {

           uiWebViewObjectPtrs.forEach(function(ptrStr) {
             var UIWebView = new ObjC.Object(ptr(ptrStr));
             console.log(red, "[+]", reset, "UIWebView detected", reset);
             console.log(cyan, "[+]", reset, "Title: n/a");
             console.log(cyan, "[+]", reset, "URL:", uiWebViewlastAccessedURL);
             console.log(red, "[+]", reset, "JavaScript: Enabled");
             console.log(red, "[+]", reset, "JavaScriptCanOpenWindowsAutomatically: Enabled");
             console.log(red, "[+]", reset, "Mixed Content: Enabled");
             console.log(red, "[+]", reset, "Allow File Access: Enabled");
             console.log(red, "[+]", reset, "Allow File Access From File URLs: Enabled");
             console.log(red, "[+]", reset, "Allow Universal Access from Files (Same-Origin Policy Ignored): Enabled\n");
           });

           wkWebViewObjectPtrs.forEach(function(ptrStr) {
             var WKWebView = new ObjC.Object(ptr(ptrStr));
             var WKWebViewConfiguration = new ObjC.Object(ptr(WKWebView.configuration())); // Creating a new object from the configuration pointer results in EXC_BAD_ACCESS
             var WKPreferences = new ObjC.Object(ptr(WKWebViewConfiguration.preferences()));
             var WKUserContentController = new ObjC.Object(ptr(WKWebViewConfiguration.userContentController()));

             var javaScriptEnabled = WKPreferences.javaScriptEnabled();
             var hasOnlySecureContent = WKWebView.hasOnlySecureContent();
             var javaScriptCanOpenWindowsAutomatically = WKPreferences.javaScriptCanOpenWindowsAutomatically();
             var title = WKWebView.title();

             console.log(green, "[+]", reset, "WKWebView detected");
             if(title != "") {
               console.log(cyan, "[+]", reset, "Title:", title);
             } else {
               console.log(cyan, "[+]", reset, "Title: No title set");
             }
             console.log(cyan, "[+]", reset, "URL:", WKWebView.URL());
             if(javaScriptEnabled) {
               console.log(yellow, "[+]", reset, "JavaScript: Enabled");
             } else {
               console.log(green, "[+]", reset, "JavaScript: Disabled");
             }
             if(javaScriptCanOpenWindowsAutomatically) {
               console.log(red, "[+]", reset, "JavaScript Can Open Windows Automatically: Enabled");
             } else {
               console.log(green, "[+]", reset, "JavaScript Can Open Windows Automatically: Disabled");
             }
             if(hasOnlySecureContent) {
               console.log(green, "[+]", reset, "Mixed Content: Disabled");
             } else {
               console.log(red, "[+]", reset, "Mixed Content: Enabled");
             }
             console.log(yellow, "[+]", reset, "Access to Local Files: Enabled");
             if(wkAccessFilesFromFileURLs) {
               console.log(red, "[+]", reset, "Access to Files from Files: Enabled");
             } else {
               console.log(green, "[+]", reset, "Access to Files from Files: Disabled");
             }
             wkAccessFilesFromFileURLs = false;
             console.log(green, "[+]", reset, "Universal Access from Files (Same-Origin Policy Ignored): Disabled\n");

           });
         }
       },
     });

     // This hook handles detecting any dynamically generated JavaScript that is evaluated within a WebView
     var uiWebViewJSEvals = resolver.enumerateMatchesSync('-[UIWebView stringByEvaluatingJavaScriptFromString:]');
     var wkWebViewJSEvals = resolver.enumerateMatchesSync('-[WKWebView evaluateJavaScript:completionHandler:]');

     uiWebViewJSEvals.forEach(function(instance) {
       Interceptor.attach(instance.address, {
         onEnter: function(args) {
           console.log(red, "[UIWebView] Dynamic JavaScript Evaluation in WebView Detected", reset);
           console.log("\tString evaluated as JavaScript: ",yellow , ObjC.Object(ptr(args[2])).toString(), reset);
         },
       });
     });

     wkWebViewJSEvals.forEach(function(instance) {
       Interceptor.attach(instance.address, {
         onEnter: function(args) {
           console.log(red, "[WKWebView] Dynamic JavaScript Evaluation in WebView Detected", reset);
           console.log("\tString evaluated as JavaScript: ",yellow , ObjC.Object(ptr(args[2])).toString(), reset);
         },
       });
     });

     // This hook detects any WKScriptMessageHandlers being registered to the WebView. These can indicate the presence
     // of a JavaScript bridge
     var wkWebViewJSHandlers = resolver.enumerateMatchesSync('-[WKUserContentController addScriptMessageHandler:name:]');

     wkWebViewJSHandlers.forEach(function(instance) {
       Interceptor.attach(instance.address, {
         onEnter: function(args) {
           console.log(yellow, "[WKWebView] Message Handler Registered (Could be a JavaScript bridge)", reset)
           console.log("\tHandler name: ", cyan, ObjC.Object(ptr(args[3])).toString(), reset);
         },
       });
     });

     // This hook detects if a WKWebView is explicitly allowing files access from files. This is a private API
     // so shouldn't pass App Store Review
     var wkWebViewPrefsSetters = resolver.enumerateMatchesSync('-[WKPreferences _setAllowFileAccessFromFileURLs:]');

     wkWebViewPrefsSetters.forEach(function(instance) {
       Interceptor.attach(instance.address, {
         onEnter: function(args) {
           if(args[2] != 0) {
             console.log(red, "[WKWebView] Allow file access from file URLs explicitly allowed", reset);
             wkAccessFilesFromFileURLs = true;
           } else {
             console.log(yellow, "[WKWebView] Suspicious modification of allow file access from file URLs key", reset);
           }
         },
       });
     });

     // This hook detects UIWebView loadHTMLString(_:baseURL:) calls where baseURL is null, which means the WebView will
     // accept applewebdata:// which allows for local file retreival
     var uiWebViewLoadHTMLStrings = resolver.enumerateMatchesSync('-[UIWebView loadHTMLString:baseURL:]');

     uiWebViewLoadHTMLStrings.forEach(function(instance) {
       Interceptor.attach(instance.address, {
         onEnter: function(args) {
           var value = ObjC.Object(ptr(args[3])).toString();
           if(value == "nil") {
             console.log(red, "[UIWebView] HTML file loaded with nil baseURL value (check for applewebdata://)", reset);
           }
         },
       });
     });

   } catch(err) {
     console.log(red, "[!] An exception occured: ", reset, err.message);
   }
 } else {
   console.log(red, "[-] Objective-C runtime is not available.", reset);
 }

 console.log(cyan, "[*] WebView implementations are now being inspected", reset);
