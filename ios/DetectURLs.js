/*
 * Title: DetectURLs
 *
 * Description: This Frida script is used to hook the -[UIApplication canOpenURL:] method which is
 * called whenever the application wants to perform file I/O. It should also print out the URL
 * it was accessing.
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

console.log(magenta, "[*] Starting URL detector script.", reset);

if(ObjC.available) {
	try {
		var className = "UIApplication";
		var methodName = "- canOpenURL:"
		var oldImpl = eval('ObjC.classes.' + className + '["' + methodName + '"]');

		Interceptor.attach(oldImpl.implementation, {
			onEnter: function(args) {
				// args[0] = self
				// args[1] = selector (method name)
				// args[2] = first argument

				//console.log("\n[+] Hooked " + className + '["' + methodName + '"]');

				var myNSUrl = new ObjC.Object(args[2]);
				var convUrl = myNSUrl.absoluteString().toString();
				console.log(bold, green, "[+] Launching URL: ", reset, convUrl);
			},

			onLeave: function(retval) {
				//console.log(cyan, "[*] Exiting method", reset);
			}
		});
	} catch(err) {
		console.log(red, "[!] An exception occured: ", reset, err.message);
	}
} else {
	console.log(red, "[-] Objective-C runtime is not available.", reset);
}

console.log(cyan, "[*] Detection of URLs is now running", reset);
