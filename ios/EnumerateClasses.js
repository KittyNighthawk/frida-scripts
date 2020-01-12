/*
 * Title: EnumerateClasses
 *
 * Description: This Frida script hooks all the classes of an application and prints their names to console. It produces a lot of
 * output as it does not remove standard iOS SDK classes.
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

console.log(magenta, "[*] Starting enumerate classes script", reset);

if(ObjC.available) {
  try {
    var classes = [];

    for (var class_name in ObjC.classes) {
      console.log(bold, green, "[+] Class found: ", class_name, reset);
    }
  } catch(err) {
    console.log(red, "[!] An exception occured: ", reset, err.message);
  }
} else {
  console.log(red, "[-] Objective-C runtime is not available.", reset);
}

console.log(cyan, "[*] Enumerate classes script complete", reset);
