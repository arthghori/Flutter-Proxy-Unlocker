# Flutter-Proxy-Unlocker

Flutter-Proxy-Unlocker is a Frida-based toolkit for intercepting and redirecting network traffic from Flutter applications on Android and iOS. It dynamically discovers and hooks internal Flutter engine functions to bypass SSL/TLS certificate validation and transparently reroute socket connections to a Burp Suite proxy. It supports arm64 and x86_64 architectures and works without repackaging, intended only for authorized mobile security testing.

## Usage

### Android

```bash
frida-ps -Uai
```
Attach to a running process
```bash
frida -Uf com.example.myapp -l FlutterProxy.js
```

### iOS (Jailbroken)

```bash
frida-ps -Uai
```
Attach to a running process
```bash
frida -Uf com.example.myapp -l FlutterProxy.js
```

## Proof of Concept (PoC)

### **Step 1 — Start Burp Suite Proxy on the Host Machine**
Open Burp Suite and enable the Proxy listener.

- Go to **Proxy → Options → Proxy Listeners**
- Ensure your listener is active (IP `192.168.x.x`, Port `8080`)
- **Tick the checkbox: "Support invisible proxying"**
  - This is required because Flutter sockets are raw TCP, not browser-style HTTP

Make sure your device and host machine are on the same network.

<img width="938" height="445" alt="Burpsuite proxy Setup" src="https://github.com/user-attachments/assets/1a6dba39-963c-4f65-85fa-9ea70991149b" />

---

### **Step 2 — Specify Burp IP and Port in the Script**
At the **very end** of `FlutterProxy.js`, configure your proxy:

```js
BURP_PROXY_IP = "192.168.x.x";   // your host machine IP
BURP_PROXY_PORT = 8080;          // your Burp proxy port
```

<img width="932" height="477" alt="Script changes IP and PORT" src="https://github.com/user-attachments/assets/14e382f3-3e8c-44b2-89dd-d80ae1d5a8a8" />

---
### **Step 3 — Attach Frida to the Flutter App**

Run this command in CMD/Terminal:
```bash
frida -Uf <package_name> -l FlutterProxy.js
```

https://github.com/user-attachments/assets/60f1e7e2-73ef-4488-a1e3-4f8550623724




