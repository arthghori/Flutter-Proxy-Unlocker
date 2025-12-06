# Flutter-Proxy-Unlocker

Flutter-Proxy-Unlocker is a Frida-based toolkit for intercepting and redirecting network traffic from Flutter applications on Android and iOS. It dynamically discovers and hooks internal Flutter engine functions to bypass SSL/TLS certificate validation and transparently reroute socket connections to a Burp Suite proxy. It supports arm64 and x86_64 architectures and works without repackaging, intended only for authorized mobile security testing.

## Usage

### Android

#### List running apps
```bash
frida-ps -Uai
```
Spawn the app with the script
```bash
frida -U -f com.example.myapp -l FlutterProxy.js
```
Attach to a running process
```bash
frida -U -n com.example.myapp -l FlutterProxy.js
```

