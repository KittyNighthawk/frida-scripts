"""
 * Title: HookBeforeAppDelegate
 *
 * Description: This python script will use the Frida module to spawn an application, and instrument it
 * before AppDelegate can perform any actions (such as performing actions within the applicationDidBecomeActive(_:)
 * function). This is useful for bypassing initial start checks like jailbreak detection or certificate pinning.
 *
 * It will load the actual hooking script from the current working directory.
 *
 * Created by Kitty Nighthawk 2020
"""
import frida
import sys

# Constant values for the ANSI colour codes
reset = "\x1b[0m"
black = "\u001b[30m"
red = "\u001b[31m"
green = "\u001b[32m"
yellow = "\u001b[33m"
blue = "\u001b[34m"
magenta = "\u001b[35m"
cyan = "\u001b[36m"
white = "\u001b[37m"
bold = "\u001b[1m"

# Enumerate the connected device and make a reference to it
device = frida.get_usb_device()

# Spawn the application on the device (process spawns and is paused) - change the application identifier as needed
pid = device.spawn(['com.apple.calculator'])

# Callback function that will print what Frida outputs to the console
def on_message(message, data):
    print(message)
    print(data)

# Attach to the process that was spawned
session = device.attach(pid)

# Load the JavaScript script from the current working directory
script = session.create_script(open("DetectJailbreakChecks.js").read())

# When Frida returns something, print it to the console
script.on('message', on_message)

# Load the script (which will perform the hooking)
script.load()

# Resume the process (which loads the application and runs it)
device.resume(pid)

# Keep the script running with this
print(cyan + '[*] Keeping script alive... CTRL+C to stop' + reset)
sys.stdin.read()
