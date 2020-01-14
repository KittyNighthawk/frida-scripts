/*
 * Title: EnumerateLoadedModules
 *
 * Description: This Frida script will enumerate the modules loaded into the current process (i.e the application being instrumented). This
 * is helpful to identify additional frameworks and technologies being employed by the application.
 *
 * By default, this will only output the module names, for further information set the verbose property to true.
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

 // Set this to true if you require more information about the loaded modules
 var verbose = false;

 console.log(magenta, "[*] Starting to enumerate loaded modules for process:", Process.id, reset);

 if(ObjC.available) {
   try {
     // This enumerate modules loaded into the current process space
     Process.enumerateModules({
       onMatch: function(module){
         if(!verbose) {
           console.log(bold, green, "[+] Loaded module:", reset, module.name);
         } else {
           console.log(bold, green, "[+] Loaded module:", reset, module.name, "(BaseAddr: " + module.bash + ", ModuleSize: " + module.size + ", ModulePath: " + module.path + ")");
         }

       },
       onComplete: function(){
         // Left in for code consistency
       }
     });
   } catch(err) {
     console.log(red, "[!] An exception occured: ", reset, err.message);
   }
 } else {
   console.log(red, "[-] Objective-C runtime is not available.", reset);
 }

 console.log(cyan, "[*] Enumeration of loaded modules complete", reset);
