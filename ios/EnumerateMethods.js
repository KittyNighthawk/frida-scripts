/*
 * Title: EnumerateMethods
 *
 * Description: This Frida script is used to hook a class and print out all the methods of
 * that class
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

console.log(magenta, "[*] Started method enumeration script", reset);

if (ObjC.available) {
	try {
		var className = "MyClassName";
		var methods = eval('ObjC.classes.' + className + '.$methods');

		for (var i=0; i<methods.length; i++) {
			try {
				console.log(bold, green, "[+] Method enumerated: ", methods[i], reset);
			} catch(err) {
				console.log(red, "[!] An excepion occured whilst printing the methods: ", err.message, reset);
			}
		}
	} catch(err) {
		console.log(red, "[!] An exception occured whilst enumerating methods: ", err.message, reset);
	}
} else {
	console.log(red, "[-] Objective-C runtime is not available.", reset);
}

console.log(cyna, "[*] Enumerate methods script complete", reset);
