/**
 * Title: DisplayUIAlert
 * 
 * Description: This Frida script demonstrates that instrumentation is possible in a pratical way, by displaying
 * a UIAlert
 * 
 * Created by KittyNighthawk (2022)
 */

 //MARK: - ANSII Colours
 const RESET = "\x1b[0m";
 const BLACK = "\u001b[30m";
 const RED = "\u001b[31m";
 const GREEN = "\u001b[32m";
 const YELLOW = "\u001b[33m";
 const BLUE = "\u001b[34m";
 const MAGENTA = "\u001b[35m";
 const CYAN = "\u001b[36m";
 const WHITE = "\u001b[37m";
 const BOLD = "\u001b[1m";

 // This is the entry point for this script
if(ObjC.available) {
    console.log(`${MAGENTA}[*] Displaying a UIAlert${RESET}\n`); 
    try {
        main();
    } catch(err) {
        console.log(`${RED}[!] An exception occured: ${RESET}${err.message}\n`);
    }
} else {
    console.log(`${RED}[-] Objective-C runtime is not available${RESET}\n`);
}

function main() {
    var handler = new ObjC.Block({
        retType: 'void',
        argTypes: ['object'],
        implementation: function () {
        }
    });

    var UIAlertController = ObjC.classes.UIAlertController;
    var UIAlertAction = ObjC.classes.UIAlertAction;
    var UIApplication = ObjC.classes.UIApplication;
    
    ObjC.schedule(ObjC.mainQueue, function () {
        var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Oh no! My main thread!', 'I am the great and powerful Mushu! 🐉', 1);
        var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
        alert.addAction_(defaultAction);
        UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
  });
}
