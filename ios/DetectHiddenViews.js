/*
 * Title: DetectHiddenViews
 *
 * Description: This Frida script is used to detect when a scene has changed, and then extract the UIWindow contents
 * and search through it for hidden views.
 *
 * The idea is that this script is run during application discovery. It will print out any hidden views it sees
 * as you traverse the application.
 *
 * This script works by hooking any calls to viewDidAppear: which is a function of View Controllers. In this case, we
 * only want to hook viewDidAppear functions whose class is not UINavigationController (the superclass) but of the
 * individual, unique subclassess (the View Controllers of each scene in the application). Once hooked, it can be
 * assumed that a new scene has been loaded, so we extract the contents of the UIWindow of that scene (this holds
 * all the other views within it) and then use a regular expression to identify any views with the hidden attribute
 * set to 'YES'
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

console.log(magenta, "[*] Starting hidden view detector script.", reset);

if(ObjC.available) {
  try {
    Interceptor.attach(ObjC.classes.UIViewController['- viewDidAppear:'].implementation, {
      onEnter: function (args) {
        /* args[0] is 'self'
         * args[1] is the selector (the funtion name)
         * args[2] is the first argument to the function
         */

         // Need to detect viewDidLoad calls on non UIViewController classes. This will be the custom views
         var className = ObjC.Object(args[0]).$className;

         if(className != "UINavigationController") {
           // Print the View Controller's name
           console.log(cyan, "[*] View Controller name: ", reset, className);
           // Pull all the UIWindow information
           var windowData = ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();

           try {
             // Search for 'hidden = YES', then print out the line
             // keyWindow will output a multiline string, so need to use global 'g' and multiline 'm' regex flags
             var regex = /^.*(<.*hidden\s=\s[yes|YES].*>).*$/gm;
             var line = regex.exec(windowData);

             // As the string is multiline, this loops through it finding each match.
             // This while loop will run as long as a match is found (if nothing is found, then line will equal null)
             while(line != null) {
               // Print the current match
               // line[0] = whole match
               // line[1] = first group of match
               console.log(bold, green,"[+] Hidden view detected: ", reset, line[1]);
               // Now continue searching the string for any other matches
               line = regex.exec(windowData);
             }
           } catch(err) {
             console.log(red, "[!] An error occured whilst parsing: ", reset, err.message);
           }
         }
      },
      onLeave: function (retval) {
        // Left blank for code consistency
      }
    });
  } catch(err) {
    console.log(red, "[!] An exception occured: ", reset, err.message);
  }
} else {
  console.log(red, "[-] Objective-C runtime is not available.", reset);
}

console.log(cyan, "[*] Detection of hidden views is now running", reset);
