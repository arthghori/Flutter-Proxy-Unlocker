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

### **Step 1: Start Burp Suite Proxy on the Host Machine**
Open Burp Suite and enable the Proxy listener.

- Go to **Proxy → Options → Proxy Listeners**
- Ensure your listener is active (IP `192.168.x.x`, Port `8080`)
- **Tick the checkbox: "Support invisible proxying"**
  - This is required because Flutter sockets are raw TCP, not browser-style HTTP

Make sure your device and host machine are on the same network.

<img width="938" height="445" alt="Burpsuite proxy Setup" src="https://github.com/user-attachments/assets/1a6dba39-963c-4f65-85fa-9ea70991149b" />

---

### **Step 2: Specify Burp IP and Port in the Script**
At the **very end** of `FlutterProxy.js`, configure your proxy:

```js
BURP_PROXY_IP = "192.168.x.x";   // your host machine IP
BURP_PROXY_PORT = 8080;          // your Burp proxy port
```

<img width="932" height="477" alt="Script changes IP and PORT" src="https://github.com/user-attachments/assets/14e382f3-3e8c-44b2-89dd-d80ae1d5a8a8" />

---
### **Step 3: Attach Frida to the Flutter App**

Run this command in CMD/Terminal:
```bash
frida -Uf <package_name> -l FlutterProxy.js
```

https://github.com/user-attachments/assets/f5cec8ce-946e-4792-93ea-9f26934a089d

## Note

**Emulator Users (Nox / Android Studio / BlueStacks)**

Do **not** configure the proxy in the emulator's WiFi settings.</br>
Instead, just set your host machine's gateway IP directly in the script

## Troubleshooting — Still Not Getting Requests in Burp?

If requests are still not showing in Burp Suite after following the steps above, try this method:

### Step 1 — Check Your Emulator Network
```bash
adb shell ip route
```
Note the network range (e.g. `172.17.100.0/24`)

---
<img width="1038" height="97" alt="image" src="https://github.com/user-attachments/assets/b966bb9b-5f53-4e03-a8f6-66d1992e697a" />

### Step 2 — Find the Default Gateway IP
```bash
adb shell ip route show table all
```
Look for the line starting with `default via`:
```
default via 172.17.100.2 dev wlan0  ← this is your host IP from emulator
```

---

<img width="695" height="391" alt="image" src="https://github.com/user-attachments/assets/c8d75962-0f3d-4954-8c06-f79bc2752eb4" />

### Step 3 — Verify the Gateway is Reachable
```bash
adb shell ping -c 3 172.17.100.2
```
Expected output (success ✅):
```
64 bytes from 172.17.100.2: icmp_seq=1 ttl=64 time=2.34 ms
64 bytes from 172.17.100.2: icmp_seq=2 ttl=64 time=1.12 ms
64 bytes from 172.17.100.2: icmp_seq=3 ttl=64 time=1.56 ms
```
If you see timeouts ❌ — check your Windows Firewall and allow Burp Suite/Java through it.

---

### Step 4 — Update the Script with Gateway IP
```js
BURP_PROXY_IP = "172.17.100.2";  // default via IP from Step 2
BURP_PROXY_PORT = 8083;           // must match your Burp listener port
```

---
<img width="679" height="241" alt="image" src="https://github.com/user-attachments/assets/444838f7-99dc-4748-94d9-0ebd70f7ac77" />

### Step 5 — Run Frida Again
```bash
frida -Uf com.example.myapp -l FlutterProxy.js
```
You should now see in the Frida console:
```
[*] Overwrite sockaddr as our burp proxy ip and port --> 172.17.100.2:8083 ✅
```
And requests will appear in **Burp → Proxy → HTTP History** 🎉





