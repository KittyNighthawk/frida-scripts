/**
 * Title: EnumerateFileDataProtectionClasses
 * 
 * Description: This Frida script enumerates all the files and directories in an applications sandbox including their data
 * protection classes. Additionally, options can be enabled to filter out secure file system objects and create a CSV
 * output of the files found to be placed into evidence tables.
 * 
 * Created by KittyNighthawk (2021)
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

//MARK: - Options
// This will display the environment URLs for the application
const SHOW_ENVIRONMENT_URLS = true;
//  This will output all environment URLs for the application (if SHOW_ENVIRONMENT_URLS is true)
const SHOW_ALL_ENVIRONMENT_URLS = true;
// This will filter out any file system objects that are considered secure or exempt
const FILTER_DATA_PROTECTION_CLASSES = false;
// This will output the results as a list on the CLI
const OUTPUT_AS_LIST = true;
// This will output a CSV formatted chunk onto the CLI
const OUTPUT_AS_CSV = false;
// For debugging
const DEBUG_ENABLED = false;
// 1 (name, type, URL, readable, writable, data protection class)
// 2 (name, type, URL, readable, writable, owner, group, data protection class, created time, modified time)
// Affects both list and CSV formats
const VERBOSITY_LEVEL = 1;

//MARK: - Properties
const NSFileManager = ObjC.classes.NSFileManager;
const NSString = ObjC.classes.NSString;
const fileManager = NSFileManager.defaultManager();
const NSBundle = ObjC.classes.NSBundle;
const bundleManager = NSBundle.mainBundle();
const regexMatchURLScheme = /(^\w+:|^)\/\//;

//MARK: - NSSearchPathDirectory enums
const NSSearchPathDirectory = {
    NSApplicationDirectory: 1,
    NSDemoApplicationDirectory: 2,
    NSDeveloperApplicationDirectory: 3,
    NSAdminApplicationDirectory: 4,
    NSLibraryDirectory: 5,
    NSDeveloperDirectory: 6,
    NSUserDirectory: 7,
    NSDocumentationDirectory: 8,
    NSDocumentDirectory: 9,
    NSCoreServiceDirectory: 10,
    NSAutosavedInformationDirectory: 11,
    NSDesktopDirectory: 12,
    NSCachesDirectory: 13,
    NSApplicationSupportDirectory: 14,
    NSDownloadsDirectory: 15,
    NSInputMethodsDirectory: 16,
    NSMoviesDirectory: 17,
    NSMusicDirectory: 18,
    NSPicturesDirectory: 19,
    NSPrinterDescriptionDirectory: 20,
    NSSharedPublicDirectory: 21,
    NSPreferencePanesDirectory: 22,
    NSApplicationScriptsDirectory: 23,
    NSItemReplacementDirectory: 99,
    NSAllApplicationsDirectory: 100,
    NSAllLibrariesDirectory: 101,
    NSTrashDirectory: 102,
};

//MARK: - NSUSearchPathDomainMask enums
const NSSearchPathDomainMask = {
    NSUserDomainMask: 1,
    NSLocalDomainMask: 2,
    NSNetworkDomainMask: 4,
    NSSystemDomainMask: 8,
    NSAllDomainsMask: 65535,
};

//MARK: - NSFileAttributeType
const NSFileAttributeType = {
    "NSFileTypeBlockSpecial": "Block special file",
    "NSFileTypeCharacterSpecial": "Character special file",
    "NSFileTypeDirectory": "Directory",
    "NSFileTypeRegular": "File",
    "NSFileTypeSocket": "Socket",
    "NSFileTypeSymbolicLink": "Symbolic link",
    "NSFileTypeUnknown": "Unknown",
};

//MARK: - UID to Username
const users = {
    "-2": "nobody",
    "0": "root",
    "501": "mobile",
    "1": "daemon",
    "98": "_ftp",
    "24": "_networkd",
    "25": "_wireless",
    "33": "_installd",
    "34": "_neagent",
    "35": "_ifccd",
    "64": "_securityd",
    "65": "_mdnsresponder",
    "75": "_sshd",
    "99": "_unknown",
    "241": "_distnote",
    "245": "_astris",
    "249": "_ondemand",
    "254": "_findmydevice",
    "257": "_datadetectors",
    "258": "_captiveagent",
    "263": "_analyticsd",
    "266": "_timed",
    "267": "_gpsd",
    "268": "_nearbyd",
    "269": "_reportmemoryexception",
};

// fsObjects holds enumerated fsObjects
var fsObjects = [];

console.log(`${MAGENTA}[*] Enumerating filesystem objects for the application${RESET}\n`); 

// This is the entry point for this script
if(ObjC.available) {
    try {
        main();
    } catch(err) {
        console.log(`${RED}[!] An exception occured: ${RESET}${err.message}\n`);
    }
} else {
    console.log(`${RED}[-] Objective-C runtime is not available${RESET}`);
}

// getURLForLocation takes in a NSSearchPathDirectory (int) and NSSearchPathDomainMask (int) and returns the URL for that location
function getURLForLocation(searchPathDirectory, searchPathDomainMask) {
    const url = fileManager.URLsForDirectory_inDomains_(searchPathDirectory, searchPathDomainMask).lastObject();

    if(url) {
        // Remove protocol handler (file://) if it is present
        return cleanURL(url.toString());
    } else {
        return "-";
    }
}

// cleanURL takes in a URL string and removes any URL schemes from the beginning of a URL
function cleanURL(url) {
    // First, check that there is a URL scheme in the url
    if (regexMatchURLScheme.exec(url)) {
        // If there is, replace the matched group with nothing
        return url.replace(regexMatchURLScheme, '');
    } else{
        // Otherwise, there is no URL scheme so just return the url
        return url;
    }
}

// printCorePaths will print out the environment URLs for the app. allPaths determines whether to display the basic paths
// or all possible paths
function printCorePaths(allPaths = false) {
    if (!allPaths) {
        console.log(`${GREEN}[*] Application environment URLs:${RESET}`);
        console.log(`${GREEN}[+] Bundle: ${bundleManager.bundlePath()}${RESET}`);
        console.log(`${GREEN}[+] Documents: ${getURLForLocation(NSSearchPathDirectory.NSDocumentDirectory, NSSearchPathDomainMask.NSUserDomainMask)}${RESET}`);
        console.log(`${GREEN}[+] Library: ${getURLForLocation(NSSearchPathDirectory.NSLibraryDirectory, NSSearchPathDomainMask.NSUserDomainMask)}${RESET}`);
        console.log("");
    } else {
        console.log(`${GREEN}[*] Application environment URLs:${RESET}`)
        for (var key in NSSearchPathDirectory) {
            const path = getURLForLocation(NSSearchPathDirectory[key], NSSearchPathDomainMask.NSUserDomainMask);
            if(path) {
                console.log(`${GREEN}[+] ${key}: ${path}${RESET}`);
            } else {
                console.log(`${GREEN}[+] ${key}: -${RESET}`);
            }
        }
        console.log("");
    }
}

// getDirectoryContents will enumerate all the file system objects from the specified URL and output their attributes
function getDirectoryContents(url) {
    var contents = fileManager.contentsOfDirectoryAtPath_error_(url, NULL);
    var recurse = true;

    // Create an array
    var fsObjects = [];

    // For each item in the directory, create a new object
    var numberOfObjects;

    if (contents !== null) {
        numberOfObjects = contents.count();
    } else {
        numberOfObjects = 0;
    }

    for(var i = 0; i < numberOfObjects; i++) {
        var file = contents.objectAtIndex_(i);
    
        var fsObject = {
            name: file.toString(),
            type: 'Unknown',
            isDirectory: null,
            url: url + "/" + file.toString(),
            owner: 'Unknown',
            group: 'Unknown',
            readable: false,
            writable: false,
            dataProtectionClass: '',
            createdTime: 'Unknown',
            modifiedTime: 'Unknown',
            allAttributes: null,
        };

        var read = fileManager.isReadableFileAtPath_(fsObject.url);
        var write = fileManager.isWritableFileAtPath_(fsObject.url);

        fsObject.readable = read;
        fsObject.writable = write;

        var attributes = fileManager.attributesOfItemAtPath_error_(fsObject.url, NULL);
        if (attributes) {
            fsObject.allAttributes = attributes;
            var enumerator = attributes.keyEnumerator();

            var key;
            while ((key = enumerator.nextObject()) !== null) {
                if (key == "NSFileProtectionKey") {
                    var value = attributes.objectForKey_(key);
                    if (value) {
                        fsObject.dataProtectionClass = value;
                    } else {
                        fsObject.dataProtectionClass = "NSFileProtectionNone";
                    }
                } else if (key == "NSFileType") {
                    var value = attributes.objectForKey_(key);
                    if (value) {
                        fsObject.type = NSFileAttributeType[value];
                        if (value == NSFileAttributeType["NSFileTypeDirectory"]) {
                            fsObject.isDirectory = true;
                        } else {
                            fsObject.isDirectory = false;
                        }
                    }
                } else if (key == "NSFileOwnerAccountName") {
                    var value = attributes.objectForKey_(key);
                    if (value) {
                        fsObject.owner = value;
                    }
                } else if (key == "NSFileGroupOwnerAccountName") {
                    var value = attributes.objectForKey_(key);
                    if (value) {
                        fsObject.group = value;
                    }
                } else if (key == "NSFileCreationDate") {
                    var value = attributes.objectForKey_(key);
                    if (value) {
                        fsObject.createdTime = value;
                    }
                } else if (key == "NSFileModificationDate") {
                    var value = attributes.objectForKey_(key);
                    if (value) {
                        fsObject.modifiedTime = value;
                    }
                } else { continue; }
            }
        }
        
        /* Example attributes
        NSFileOwnerAccountID 501
        NSFileSystemFileNumber 12885684640
        NSFileExtensionHidden 0
        NSFileSystemNumber 16777221
        NSFileSize 96
        NSFileGroupOwnerAccountID 501
        NSFileOwnerAccountName mobile
        NSFileCreationDate 2020-08-04 16:04:25 +0000
        NSFilePosixPermissions 493
        NSFileProtectionKey NSFileProtectionComplete
        NSFileType NSFileTypeDirectory
        NSFileGroupOwnerAccountName mobile
        NSFileReferenceCount 3
        NSFileModificationDate 2020-08-04 16:04:40 +0000
        */

        // Clean the URL by removing any double slashes
        fsObject.url = fsObject.url.replace(/\/\/+/g, '/');
        fsObjects.push(fsObject);

        if (DEBUG_ENABLED) {
            console.log(`${GREEN}[[DBG]] Name: ${fsObject.name}${RESET}`);
            console.log(`${GREEN}[[DBG]] Type: ${fsObject.type}${RESET}`);
            console.log(`${GREEN}[[DBG]] URL: ${fsObject.url}${RESET}`);
            console.log(`${GREEN}[[DBG]] Owner: ${fsObject.owner}${RESET}`);
            console.log(`${GREEN}[[DBG]] Group: ${fsObject.group}${RESET}`);
            console.log(`${GREEN}[[DBG]] Readable: ${fsObject.readable}${RESET}`);
            console.log(`${GREEN}[[DBG]] Writable: ${fsObject.writable}${RESET}`);
            console.log(`${GREEN}[[DBG]] Created: ${fsObject.createdTime}${RESET}`);
            console.log(`${GREEN}[[DBG]] Modified: ${fsObject.modifiedTime}${RESET}`);
            if (fsObject.dataProtectionClass != "") {
                console.log(`${GREEN}[[DBG]] Data protection class: ${fsObject.dataProtectionClass}${RESET}`);
            } else {
                console.log(`${GREEN}[[DBG]] Data protection class: NSFileProtectionNone${RESET}`);
            }
            console.log();
        } 

        if (fsObject.dataProtectionClass == "" || fsObject.dataProtectionClass == "None") {
            fsObject.dataProtectionClass = "NSFileProtectionNone";
        }

        if (recurse) {
            if (fsObject.type == "Directory") {
                fsObjects.push(getDirectoryContents(fsObject.url));
            } 
        }   
    }
    return fsObjects;
}

// formatAsCSV takes an array of file system objects and outputs a CSV formatted chunk of text to the CLI. verbosityLevel
// determines how much information to include
function formatAsCSV(fsObjects, verbosityLevel = 1) {
    var content = "";

    if (verbosityLevel == 1) {
        content += "name,type,url,readable,writable,data-protection-class\n";
    } else if (verbosityLevel == 2) {
        content += "name,type,url,owner,group,readable,writable,data-protection-class,createOn,lastModifiedOn\n";
    }

    //var content = "name,type,url,readable,writable,data-protection-class\n";

    var recurseFsObject = function (arr) {
        arr.forEach(function (fsObject) {
            if (typeof fsObject == 'object' && fsObject.constructor === Array) {
                recurseFsObject(fsObject);
            }
            if (typeof fsObject.type !== 'undefined') {
                switch (verbosityLevel) {
                    case 1:
                        content += fsObject.name + ",";
                        content += fsObject.type + ",";
                        content += fsObject.url + ",";
                        content += fsObject.readable + ",";
                        content += fsObject.writable + ",";
                        content += fsObject.dataProtectionClass + "\n";
                        break;
                    case 2:
                        content += fsObject.name + ",";
                        content += fsObject.type + ",";
                        content += fsObject.url + ",";
                        content += fsObject.owner + ",";
                        content += fsObject.group + ",";
                        content += fsObject.readable + ",";
                        content += fsObject.writable + ",";
                        content += fsObject.dataProtectionClass + ",";
                        content += fsObject.createdTime + ",";
                        content += fsObject.modifiedTime + "\n";
                        break;
                    default:
                        console.log(`${RED}[ERROR] There was an error formatting the CSV content${RESET}`);
                        break;
                }
            }
        });
    }
    
    recurseFsObject(fsObjects);
    console.log(`${GREEN}*** COPY EVERYTHING BETWEEN THESE GREEN LINES ***${RESET}`);
    console.log(content);
    console.log(`${GREEN}*** NOW SAVE AS A CSV FILE ***${RESET}`);
}

// Turns an array of file system objects into a list displayed in the CLI. The verbosity level determines how much 
// data you see
function formatAsList(fsObjects, verbosityLevel = 1) {
    var recurseFsObject = function (arr, verbosityLevel) {
        arr.forEach(function (fsObject) {
            if (typeof fsObject == 'object' && fsObject.constructor === Array) {
                recurseFsObject(fsObject, verbosityLevel);
            } else if (typeof fsObject.type !== 'undefined') {
                switch (verbosityLevel) {
                    case 1:
                        console.log(`Name: ${fsObject.name}`);
                        console.log(`Type: ${fsObject.type}`);
                        console.log(`URL: ${fsObject.url}`);
                        console.log(`Readable: ${fsObject.readable}`);
                        console.log(`Writable: ${fsObject.writable}`);
                        if (fsObject.dataProtectionClass != "") {
                            console.log(`Data protection class: ${fsObject.dataProtectionClass}`);
                        } else {
                            console.log("Data protection class: None");
                        }
                        console.log();
                        break;
                    case 2:
                        console.log(`Name: ${fsObject.name}`);
                        console.log(`Type: ${fsObject.type}`);
                        console.log(`URL: ${fsObject.url}`);
                        console.log(`Owner: ${fsObject.owner}`);
                        console.log(`Group: ${fsObject.group}`);
                        console.log(`Readable: ${fsObject.readable}`);
                        console.log(`Writable: ${fsObject.writable}`);
                        console.log(`Created: ${fsObject.createdTime}`);
                        console.log(`Modified: ${fsObject.modifiedTime}`);
                        if (fsObject.dataProtectionClass != "") {
                            console.log(`Data protection class: ${fsObject.dataProtectionClass}`);
                        } else {
                            console.log("Data protection class: None");
                        }
                        console.log();
                        break;
                    default:
                        console.log("No data to display");
                }
            } else {
                //
            }
        });
    }

    recurseFsObject(fsObjects, verbosityLevel);
}

// Filters an fsObject array and returns a new array containing only those objects considered insecure
function filterSecureClassesOnly(fsObjects) {
    // These are the Data Protection Classes deemed insecure that should not be used
    const insecureDataProtectionClasses = [
        "NSFileProtectionNone",
        "NSFileProtectionCompleteUntilFirstUserAuthentication"
    ];

    // These are paths that need to be "insecure" so that iOS/iPadOS can access them for normal functionality
    const excludedPaths = [
        "/Cache.db",
        "/Cache.db-shm",
        "/Cache.db-wal",
        "/KnownSceneSessions/data.data",
        "/Library/SplashBoard/Snapshots/",
        "/SystemData/",
        ".com.apple.mobile_container_manager.metadata.plist"
    ];

    var insecureFsObjects = [];

    var recurseFsObject = function (arr) {
        arr.forEach(function (fsObject) {
            if (typeof fsObject == 'object' && fsObject.constructor === Array) {
                recurseFsObject(fsObject);
            }

            if (typeof fsObject.type !== 'undefined') {
                insecureDataProtectionClasses.forEach(function (protectionClass) {
                    if (fsObject.dataProtectionClass == protectionClass) {
                        insecureFsObjects.push(fsObject);
                    }
                });
            }
        });
    }
    recurseFsObject(fsObjects);
    return insecureFsObjects;
}

// Helper function to get the root URL of the application
function getAppRootPath(url) {
    var urlParts = url.split("/");
    urlParts.pop();
    urlParts.pop();
    return urlParts.join("/");
}

// main is the starting function for the program
function main() {
    var applicationRootPath = getAppRootPath(getURLForLocation(NSSearchPathDirectory.NSDocumentDirectory, NSSearchPathDomainMask.NSUserDomainMask));
    var fsItems = [];

    if (DEBUG_ENABLED) {
        console.log(`${GREEN}Enumerating objects from: ${applicationRootPath}${RESET}`);
    }
    
    if (SHOW_ENVIRONMENT_URLS) {
        printCorePaths(SHOW_ALL_ENVIRONMENT_URLS);
    }

    if (FILTER_DATA_PROTECTION_CLASSES) {
        fsItems = filterSecureClassesOnly(getDirectoryContents(getURLForLocation(applicationRootPath)));
    } else {
        fsItems = getDirectoryContents(applicationRootPath);
    }
    
    if (OUTPUT_AS_LIST) {
        formatAsList(fsItems, VERBOSITY_LEVEL);
    }
    
    if (OUTPUT_AS_CSV) {
        formatAsCSV(fsItems, VERBOSITY_LEVEL);
    }
}
