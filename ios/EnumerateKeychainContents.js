/**
 * Title: EnumerateKeychainContents
 * 
 * Description: This Frida script enumerates all the keys added to the Keychain by the application it injects into. Note
 * that this means it does not extract the entirety of the Keychain. It is capable of extracting a list of keys including
 * their attributes, creating a CSV of the contents for easy review, and performing fitering to only identify those
 * keys with weak properties.
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
// When enabled, this will filter out keys which have whenPasscodeSetThisDeviceOnly as the accessibility setting
const FILTER_ACCESSIBILITY_CLASS = false;
// This will output the results as a list on the CLI
const OUTPUT_AS_LIST = true;
// This will output a CSV formatted chunk onto the CLI
const OUTPUT_AS_CSV = false;
// For debugging
const DEBUG_ENABLED = false;
// 1 (key type, account name, alias, label, comment, service, access control class, accessibility class, data)
// 2 (key type, account name, alias, label, comment, service, access control class, accessibility class, access group, created on, modified on, data)
// 3 (key type, UUID, account name, alias, label, comment, service, creator, access control class, accessibility class, access group, created on, modified on, encrytped data, data, sha1, associated with another key, hidden key, generic attribute, security domain, server, authentication type, path, port)
// Affects both list and CSV formats
const VERBOSITY_LEVEL = 2;

//MARK: - Properties
var SecItemCopyMatching = new NativeFunction(ptr(Module.findExportByName('Security', 'SecItemCopyMatching')), 'pointer', ['pointer', 'pointer']);
var SecAccessControlGetConstraints = new NativeFunction(ptr(Module.findExportByName('Security', 'SecAccessControlGetConstraints')), 'pointer', ['pointer']);

// This is the entry point for this script
if(ObjC.available) {
    console.log(`${MAGENTA}[*] Enumerating Keychain keys for the application${RESET}\n`); 
    try {
        main();
    } catch(err) {
        console.log(`${RED}[!] An exception occured:${RESET} ${err.message}\n`);
    }
} else {
    console.log(`${RED}[-] Objective-C runtime is not available${RESET}\n`);
}

// main is the starting function for the program
function main() {
    var keychainKeys = [];

    if (DEBUG_ENABLED) {
        console.log(`${GREEN}Enumerating keys in Keychain${RESET}\n`);

        console.log(`${GREEN}${BOLD}DEBUG:${RESET}${GREEN}Raw Keychain contents${RESET}\n`);
        console.log(JSON.stringify(keychainKeys, null, 2));
    }

    if (FILTER_ACCESSIBILITY_CLASS) {
        keychainKeys = filterSecureAccessibilityOnly(getKeychainContents());
    } else {
        keychainKeys = getKeychainContents();
    }
    
    if (OUTPUT_AS_LIST) {
        formatAsList(keychainKeys, VERBOSITY_LEVEL);
    }
    
    if (OUTPUT_AS_CSV) {
        formatAsCSV(keychainKeys, VERBOSITY_LEVEL);
    }
}

// Gets all the keys from the Keychain the application can access. Returns an array of key objects
function getKeychainContents() {
    var keychainKeys = [];

    const keyTypes = [
        'keys',
        'idnt',
        'cert',
        'genp',
        'inet',
    ];
    const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true);
    const queryDictionary = ObjC.classes.NSMutableDictionary.alloc().init();
    queryDictionary.setObject_forKey_(kCFBooleanTrue, 'r_Attributes');
    queryDictionary.setObject_forKey_(kCFBooleanTrue, 'r_Data');
    queryDictionary.setObject_forKey_(kCFBooleanTrue, 'r_Ref');
    queryDictionary.setObject_forKey_('m_LimitAll', 'm_Limit');
    queryDictionary.setObject_forKey_('syna', 'sync');

    keyTypes.forEach(function(keyType) {
        queryDictionary.setObject_forKey_(keyType, "class");
        const keyPointer = Memory.alloc(Process.pointerSize);
        const copyResult = SecItemCopyMatching(queryDictionary, keyPointer);

        if (copyResult != 0x00) { 
            return; 
        }

        var searchResult = new ObjC.Object(Memory.readPointer(keyPointer));

        /*
        {
            UUID = "5BF65C01-A7AD-440B-8CB2-F147241999BE";
            accc = "<SecAccessControlRef: ak>";
            acct = keychainValue;
            agrp = "UAVZNE8PJA.com.highaltitudehacks.DVIAswiftv2";
            cdat = "2021-05-28 11:17:42 +0000";
            class = genp;
            mdat = "2021-05-28 11:21:26 +0000";
            musr = <>;
            pdmn = ak;
            persistref = <>;
            sha1 = <282a0d04 28a940b2 20f20019 0374a760 f51fbcd9>;
            svce = "com.highaltitudehacks.DVIAswiftv2";
            sync = 0;
            tomb = 0;
            "v_Data" = <53656372 6574556e 69636f72 6e323432 34>;
        }
        */

        if (searchResult.count() > 0) {
            // We have keys to extract
            for (var i = 0; i < searchResult.count(); i++) {
                // Now lets loop through each key
                var a = searchResult.objectAtIndex_(i);

                //console.log(a);

                // Okay, we need to extract the parts of the key and build a new object fo those extracts so we can use it later
                var key = {
                    "UUID": getStringRep(a.objectForKey_("UUID")),
                    "AccessControl": getAccessControlACLs(a),
                    "Account": getStringRep(a.objectForKey_("acct")),
                    "Alias": getStringRep(a.objectForKey_("alis")),
                    "Label": getStringRep(a.objectForKey_("labl")),
                    "Comment": getStringRep(a.objectForKey_("icmt")),
                    "Creator": getStringRep(a.objectForKey_("crtr")),
                    "AccessGroup": getStringRep(a.objectForKey_("agrp")),
                    "CreatedOn": getStringRep(a.objectForKey_("cdat")),
                    "Class": convertFourCharCode(keyType),
                    "LastModified": getStringRep(a.objectForKey_("mdat")),
                    "Accessibility": convertFourCharCode(getStringRep(a.objectForKey_("pdmn"))),
                    "EncryptedData": getStringRep(a.objectForKey_("prot")), //https://opensource.apple.com/source/Security/Security-57740.1.18/OSX/libsecurity_keychain/lib/SecKeychainItemPriv.h
                    "SHA1": formatToHexString(getStringRep(a.objectForKey_("sha1"))),
                    "Service": getStringRep(a.objectForKey_("svce")),
                    "Data": formatToHexString(getStringRep(a.objectForKey_("v_Data"))),
                    "IsVisible": a.objectForKey_("invi"),
                    "IsAssociatedToKey": a.objectForKey_('nega'),
                    "GenericAttribute": getStringRep(a.objectForKey_("gena")), //genp only
                    "SecurityDomain": getStringRep(a.objectForKey_('sdmn')), // inet only
                    "Server": getStringRep(a.objectForKey_('srvr')), //inet only
                    "AuthenticationType": getStringRep(a.objectForKey_("atyp")), // inet only
                    "Port": getStringRep(a.objectForKey_("port")), // inet only
                    "Path": getStringRep(a.objectForKey_("path")), //inet only
                };

                keychainKeys.push(key);
            }
        }
    });

    return keychainKeys;
}

// Gets the string representation of a property
function getStringRep(obj) {
    try {
        var a = new ObjC.Object(obj);
        return Memory.readUtf8String(a.bytes(), a.length());
    } catch (err) {
        try {
            return obj.toString();
        } catch (err) {
            return 'null';
        }
    }
}

// Takes a hex string and removes the spaces and special character, then returns the raw hex string
function formatToHexString(str) {
    try {
        return str.replace(/</g, "").replace(/>/g, "").replace(/\s/g, "");
    } catch (_) {
        return "null";
    }  
}

// Takes a FourCharCode and returns it's string full name
function convertFourCharCode(code) {
    switch(code) {
        case "genp": return "Generic Password";
        case "inet": return "Internet Password";
        case "cert": return "Certificate";
        case "idnt": return "Identity";
        case "keys": return "Cryptographic Key";
        case "ak": return "kSecAttrAccessibleWhenUnlocked";
        case "ck": return "kSecAttrAccessibleAfterFirstUnlock";
        case "dk": return "kSecAttrAccessibleAlways";
        case "aku": return "kSecAttrAccessibleWhenUnlockedThisDeviceOnly";
        case "akpu": return "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly";
        case "cku": return "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly";
        case "dku": return "kSecAttrAccessibleAlwaysThisDeviceOnly";
    }
}

function nullHandler(obj) {
    try {
        return obj.toString();
    } catch (_) {
        return "null";
    }
}
// Retreives the access control settings 
// https://opensource.apple.com/source/Security/Security-57336.10.29/OSX/sec/Security/SecAccessControlPriv.h.auto.html
function getAccessControlACLs(accc) {
    if (!accc.containsKey_("accc")) {
        return "None";
    }

    var acls = ObjC.Object(SecAccessControlGetConstraints(accc.objectForKey_("accc")));

    if (acls.handle == 0x00) {
        return "None";
    }

    //Use this for reverse engineering flags
    //console.log(acls);

    // At this point, I cannot find out what the individual keys in the ACL object mean, so need to do some reverse
    // engineering. But will use Senseposts (Objection) hook from 1.4.1 for now
    // https://github.com/sensepost/objection/blob/1.4.1/objection/hooks/ios/keychain/dump.js
    
    //TODO: Reverse engineer the ACL flags to determine what they all mean, then re-write this section.
    var flags = [];
    var acl_enumerator = acls.keyEnumerator();
    var acl_item_key;

    while ((acl_item_key = acl_enumerator.nextObject()) !== null) {

        var acl_item = acls.objectForKey_(acl_item_key);

        switch (getStringRep(acl_item_key)) {

            case 'dacl':
                break;
            case 'osgn':
                flags.push('PrivateKeyUsage');
            case 'od':
                var constraints = acl_item;
                var constraint_enumerator = constraints.keyEnumerator();
                var constraint_item_key;

                while ((constraint_item_key = constraint_enumerator.nextObject()) !== null) {

                    switch (getStringRep(constraint_item_key)) {
                        case 'cpo':
                            flags.push('kSecAccessControlUserPresence');
                            break;

                        case 'cup':
                            flags.push('kSecAccessControlDevicePasscode');
                            break;

                        case 'pkofn':
                            constraints.objectForKey_('pkofn') == 1 ?
                                flags.push('Or') :
                                flags.push('And');
                            break;

                        case 'cbio':
                            constraints.objectForKey_('cbio').count() == 1 ?
                                flags.push('kSecAccessControlBiometryAny') :
                                flags.push('kSecAccessControlBiometryCurrentSet');
                            break;

                        default:
                            break;
                    }
                }
                break;
            case 'prp':
                flags.push('ApplicationPassword');
                break;
            default:
                break;
        }
    }
    return flags.join(' ');
}

// Filters out all keys considered secure or exempt. Returns a filtered array of key objects
function filterSecureClassesOnly(keysArray) {
    var originalKeys = keysArray;
    var filteredKeys = [];

    // Core goes here

    return filteredKeys;
}

// Turns an array of Keychain keys into a list displayed in the CLI. The verbosity level determines how much 
// data you see
function formatAsList(keysArray, verbosityLevel = 2) {
    keysArray.forEach(function(object){
        switch(verbosityLevel) {
            case 1:
                console.log(`Key Type: ${object.Class}`);
                console.log(`Account: ${object.Account}`);
                console.log(`Alias: ${object.Alias}`);
                console.log(`Label: ${object.Label}`);
                console.log(`Comment: ${object.Comment}`);
                console.log(`Service: ${object.Service}`);
                console.log(`Access Control: ${object.AccessControl}`);
                console.log(`Accessibility: ${object.Accessibility}`);
                console.log(`Data: ${object.Data}\n`);
                break;
            case 2:
                console.log(`Key Type: ${object.Class}`);
                console.log(`Account: ${object.Account}`);
                console.log(`Alias: ${object.Alias}`);
                console.log(`Label: ${object.Label}`);
                console.log(`Comment: ${object.Comment}`);
                console.log(`Service: ${object.Service}`);
                console.log(`Access Control: ${object.AccessControl}`);
                console.log(`Accessibility: ${object.Accessibility}`);
                console.log(`Access Group: ${object.AccessGroup}`);
                console.log(`Created on: ${object.CreatedOn}`);
                console.log(`Last modified on: ${object.LastModified}`);
                console.log(`Data: ${object.Data}\n`);
                break;
            case 3:
                console.log(`Key Type: ${object.Class}`);
                console.log(`UUID: ${object.UUID}`);
                console.log(`Account: ${object.Account}`);
                console.log(`Alias: ${object.Alias}`);
                console.log(`Label: ${object.Label}`);
                console.log(`Comment: ${object.Comment}`);
                console.log(`Service: ${object.Service}`);
                console.log(`Created by: ${object.Creator}`);
                console.log(`Access Control: ${object.AccessControl}`);
                console.log(`Accessibility: ${object.Accessibility}`);
                console.log(`Access Group: ${object.AccessGroup}`);
                console.log(`Created on: ${object.CreatedOn}`);
                console.log(`Last modified on: ${object.LastModified}`);
                console.log(`Encrypted data: ${object.EncryptedData}`);
                console.log(`Data: ${object.Data}`);
                console.log(`SHA1: ${object.SHA1}`);
                console.log(`Associated to another key: ${object.IsAssociatedToKey}`);
                console.log(`Hidden Key: ${object.IsVisible}`)
                
                if(object.Class == "Internet Password") {
                    console.log(`Security Domain: ${object.SecurityDomain}`);
                    console.log(`Server: ${object.Server}`);
                    console.log(`Authentication Type: ${object.AuthenticationType}`);
                    console.log(`Path: ${object.Path}`);
                    console.log(`Port: ${object.Port}`);
                }

                if(object.Class == "Generic Password") {
                    console.log(`Generic Attribute: ${object.GenericAttribute}`);
                }

                console.log("\n");
                break;
            default:
                console.log(`Key Type: ${object.Class}`);
                console.log(`Account: ${object.Account}`);
                console.log(`Alias: ${object.Alias}`);
                console.log(`Label: ${object.Label}`);
                console.log(`Comment: ${object.Comment}`);
                console.log(`Service: ${object.Service}`);
                console.log(`Access Control: ${object.AccessControl}`);
                console.log(`Accessibility: ${object.Accessibility}`);
                console.log(`Data: ${object.Data}\n`);
                break;
        }
    });
}

// formatAsCSV takes an array of Keychain objects and outputs a CSV formatted chunk of text to the CLI. verbosityLevel
// determines how much information to include
function formatAsCSV(keysArray, verbosityLevel = 1) {
    var content = "";

    // CSV header row
    switch(verbosityLevel) {
        case 1:
            content += "keyType,account,alias,label,comment,service,accessControl,accessibility,data\n";
            break;
        case 2:
            content += "keyType,account,alias,label,comment,service,accessControl,accessibility,accessGroup,createdOn,modifiedOn,data\n";
            break;
        case 3:
            content += "keyType,uuid,account,alias,label,comment,service,createdBy,accessControl,accessibility,accessGroup,createdOn,modifiedOn,encrytpedData,data,sha1,associatedKey,hiddenKey,genericAttribute,securityDomain,server,authenticationType,path,port\n";
            break;
        default:
            break;
    }

    keysArray.forEach(function(object) {
        switch(verbosityLevel) {
            case 1:
                content += `${object.Class},${object.Account},${object.Alias},${object.Label},${object.Comment},${object.Service},${object.AccessControl},${object.Accessibility},${object.Data}\n`;
                break;
            case 2:
                content += `${object.Class},${object.Account},${object.Alias},${object.Label},${object.Comment},${object.Service},${object.AccessControl},${object.Accessibility},${object.AccessGroup},${object.CreatedOn},${object.LastModified},${object.Data}\n`;
                break;
            case 3:
                content += `${object.Class},${object.UUID},${object.Account},${object.Alias},${object.Label},${object.Comment},${object.Service},${object.Creator},${object.AccessControl},${object.Accessibility},${object.AccessGroup},${object.CreatedOn},${object.LastModified},${object.EncryptedData},${object.Data},${object.SHA1},${object.IsAssociatedToKey},${object.IsVisible},${object.GenericAttribute},${object.SecurityDomain},${object.Server},${object.AuthenticationType},${object.Path},${object.Port}\n`;
                break;
            default:
                break;
        }
    });

    console.log(`${GREEN}*** COPY EVERYTHING BETWEEN THESE GREEN LINES ***${RESET}`);
    console.log(content);
    console.log(`${GREEN}*** NOW SAVE AS A CSV FILE ***${RESET}`);
}

// This will filter out any keys with kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly is the accessibility class
// Note that kSecAttrAccessibleAfterFirstUnlock can be used only when an application needs to access keys whilst it
// is in the background. All others should be avoided
function filterSecureAccessibilityOnly(keysArray) {
    const passcodeSet = "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"; 
    var insecureObjects = [];

    keysArray.forEach(function(key) {
        if(key.Class !== passcodeSet) { insecureObjects.push(key)}
    })

    return insecureObjects;
}