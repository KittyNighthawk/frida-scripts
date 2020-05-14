# frida-scripts
A collection of Frida scripts that I created for iOS and Android mobile application assessments

To use these scripts, ensure that frida is installed on your testing machine, and frida-server is running on the mobile device. Then use the following command to use the desired script:

```
$ frida -U -l [SCRIPT-NAME].js [PROCESS-NAME]
```

You can find the process name using ```frida-ps```:

```
$ frida-ps -Uai
```

Some scripts are best run from when the application first starts. In those cases, you can use early instrumentation as shown below:

```
$ frida -U -l [SCRIPT-NAME] --no-puase -f [APP-IDENTIFIER]
```
