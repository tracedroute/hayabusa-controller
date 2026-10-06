# Privacy Policy — Hayabusa Controller

**Effective date:** September 30, 2026  
**Publisher:** TracedRoute  
**Product:** Hayabusa Controller (Windows and Linux)

This Privacy Policy describes how TracedRoute (“we,” “us,” or “our”) handles information in connection with the **Hayabusa Controller** application on **Windows** and **Linux** (the “App”), including the Microsoft Store build of the Windows version.

Contact: [support@tracedroute.net](mailto:support@tracedroute.net)

---

## 1. Summary

Hayabusa Controller is an on-premises / on-device **site edge** appliance. It is designed to run on your computer or server and operate your network site alongside **Hayabusa Core** (our control-plane / cockpit product, commonly reached at `hayabusa.tracedroute.net` or an operator-hosted Core).

- Most operational data stays **on your device** (secrets vault, site DHCP/ZTP state, local job history, and local RF/MAVLink capture when those features are used).
- When you connect the App to Hayabusa Core, limited account, enrollment, status, and **operator-requested** operational data is sent over the secure controller bridge so Core can enroll the site, show Fleet Incoming, sync Integration Builder bundles, proxy robotics/disaster radio streams you start, and run LAN-Approve jobs.
- **Secrets values** you store in the App’s vault are intended to remain on the controller and hydrate only for approved on-controller jobs — not to be stored long-term in Core.
- We do **not** sell personal information.
- We do **not** use third-party advertising SDKs or ad trackers in the App.
- The App includes open-source components. Full attribution is in **THIRD-PARTY-NOTICES.txt** (also available in-app at `/static/THIRD-PARTY-NOTICES.txt`, linked from the Controller dashboard, Administration, Workspace, Image Nest, and login pages).

---

## 2. Information we process

### 2.1 Information stored on your device

Depending on how you use the App, it may store locally on the machine where it is installed:

- On **Windows**, typically under your user profile (e.g. `%LOCALAPPDATA%\HayabusaController`) or the App’s data directory
- On **Linux**, typically under the controller data volume / data directory configured for the appliance or install (for example `/var/lib/hayabusa-controller`)

Local data may include:

- Admin / sign-in credentials you set (including a first-launch bootstrap password that you are required to replace)
- Session liability acknowledgments (accept/decline of the in-app infrastructure risk notice)
- Secrets and credentials you choose to store in the App’s secrets vault
- Sign-in allowlists (for example emails permitted to use authenticator / IdP sign-in)
- Role / access (RBAC) settings and site configuration
- Enrollment and mesh status files
- Infrastructure-as-code workspace files, job history, pending approve/hydrate jobs, and related operational state you create or import
- **Zero-touch provisioning (ZTP)** configuration and state when enabled (for example dnsmasq settings, DHCP leases, seeking/fetch journals, and related MAC/hostname/vendor-class observations on the site LAN)
- **Integration Builder** / webhook / automation bundles synced from Core when you use Integrations sync
- **Edge RF / robotics state** when those features are used (for example MAVLink session status, SDR scanner status, temporary audio buffers, and ADS-B JSON paths if dump1090 or similar tools are installed)
- Optional remote-console related configuration on builds that include that feature (Linux appliance builds may include Guacamole-related components; the Windows Store SKU does not ship full Guacamole)
- Application logs needed to run and troubleshoot the App on your machine

This local data is under your control on the device where the App is installed.

### 2.2 Account and authentication information

To sign in, you may use:

- A local admin username and password managed by the App; and/or
- Identity providers (such as Google, GitHub, Microsoft, Discord, or Slack) when enabled, typically **brokered through Hayabusa Core** so IdP client secrets are not required on the controller host; and/or
- Authenticator-app (TOTP) flows for allowlisted emails, when configured

We may process identifiers such as username, email address, identity-provider subject ID, and sign-in timestamps to authenticate you and authorize access.

### 2.3 Information sent to Hayabusa Core (control plane)

When the App is connected to Hayabusa Core, it may transmit:

- Controller enrollment and mesh join information
- Owner / operator identity associated with the enrollment (for example username, email, and identity-provider subject)
- Connection, health, hostname, VPN/mesh addressing, and coarse **site network / geo hints** derived from public or WAN addressing (used so Core can place the site on maps and default disaster-alert coordinates to the selected controller’s location when you have not overridden them)
- Operational messages over the secure controller bridge / WebSocket needed to:
  - run and report **LAN-Approve** jobs and IaC sync you request
  - relay **ZTP / DHCP lease and seeking** summaries into Core Fleet Incoming when ZTP is enabled
  - **pull/push Integration Builder** webhooks, custom apps, and automation job definitions you sync
  - answer **edge capability / status** probes and, when you operate robotics or disaster radio from Core, return **telemetry snapshots, ADS-B track summaries, and audio/PCM chunks** so Core can re-stream them to your browser (the browser talks to Core; transmit/capture remains on the controller)
- Connection and health information required to keep the mesh and control plane working

The Windows Store build pins Hayabusa Core to TracedRoute-operated hosts by default (such as `hayabusa.tracedroute.net` and related mesh endpoints). Linux deployments may use the same TracedRoute-operated Core or an operator-configured Core endpoint, depending on how the appliance is set up.

### 2.4 Network and LAN information

The App may discover or use local network information (for example LAN IP addresses, interface names, and—if you enable ZTP—DHCP client MAC addresses, hostnames, and vendor/user class strings) to bind its dashboard, display connection URLs, deliver `/ztp/fetch` payloads on the site LAN, and support mesh VPN enrollment. LAN/device details used for these features are processed to provide the functions you enable. Hub Hayabusa Core is not intended to run customer-site DHCP; site DHCP/discovery is owned by the controller when a branch is selected.

### 2.5 Robotics, radio, and airspace features

If you use Robotics Viewer, disaster/weather radio, ADS-B, or related features through Core while a controller branch is selected:

- **Capture and transmit** (SDR tune, MAVLink link, local dump1090 reads) are intended to run on the **controller**
- **Audio and telemetry** may be **proxied through Core** to your signed-in browser session for the duration of the stream or poll
- These features are for authorized operations only; you are responsible for complying with aviation, RF, Remote ID, and privacy laws in your jurisdiction

### 2.6 Information we do not collect for advertising

The App does not include third-party advertising networks, and we do not collect App usage data for advertising profiling.

---

## 3. How we use information

We use the information above to:

- Provide, operate, secure, and improve the App and Hayabusa Core
- Authenticate users and enforce access controls
- Enroll your controller, establish mesh connectivity, and sync operational state you request (including ZTP Incoming, Integration Builder bundles, and edge RF/robotics proxies you start)
- Show site context in Core (branch selection, map/geo defaults, Fleet Incoming)
- Troubleshoot issues and respond to support requests
- Meet legal, security, and compliance obligations

---

## 4. How we share information

We may share information only as needed to operate the service:

- **Hayabusa Core / TracedRoute infrastructure** — to enroll, authenticate, operate the control plane, and proxy operator-requested streams/status
- **Identity providers you choose** — when you sign in with a third-party IdP (their privacy policies also apply)
- **Networking components you use with the App** — for example Tailscale / Headscale-style mesh connectivity used for site networking
- **Service providers** who help us host or operate infrastructure, under appropriate confidentiality obligations
- **Legal / safety** — if required by law, regulation, legal process, or to protect rights, security, and integrity

We do **not** sell personal information, and we do not share personal information for cross-context behavioral advertising.

---

## 5. Third-party services and open-source components

Depending on configuration and platform SKU, the App may interact with:

- Hayabusa Core (`hayabusa.tracedroute.net` and/or operator-configured related endpoints)
- Optional identity providers (Google, GitHub, Microsoft, Discord, Slack, etc.)
- Mesh VPN components (including an open-source Tailscale/Headscale-compatible client; not Tailscale Inc’s proprietary product and not endorsed by Tailscale Inc.)
- Optional remote-console components on Linux appliance builds that include them (for example Apache Guacamole via official images)
- Optional host tools you install for edge features (for example `rtl_fm` / ffmpeg for SDR, dump1090 for ADS-B, pymavlink for MAVLink) — governed by their own licenses and notices

Those services are governed by their own terms and privacy policies when you use them.

Open-source libraries and bundled tools (Python packages, mesh client, openssh-client for controller lan.relay (Ansible/OpenTofu run on Hayabusa Core), optional Guacamole, and related notices) are listed in **THIRD-PARTY-NOTICES.txt**. That file is shipped with both the Windows and Linux versions of the App and is also available at `/static/THIRD-PARTY-NOTICES.txt` when the App is running.

---

## 6. Data retention

- **On-device data** remains until you delete it, uninstall or remove the App and clear its data directories / volumes, or otherwise clear App state on the device (including ZTP leases/journals and temporary RF buffers, which may also roll over on a short operational schedule).
- **Hayabusa Core data** associated with your enrollment, account, Incoming rows, synced integration bundles, and proxied session traffic is retained for as long as needed to provide the service, maintain security, comply with law, and resolve disputes. Live audio/telemetry proxy buffers are operational and not intended as a long-term archive. You may contact us to request deletion subject to technical and legal limits.

---

## 7. Security

We use administrative, technical, and organizational measures appropriate to the nature of a site-controller product (including encrypted transport to Hayabusa Core where applicable, local secret storage practices, LAN-Approve hydration for secret values, and access controls). No method of transmission or storage is 100% secure; you are responsible for protecting device access, admin passwords, RF/antenna exposure, and network exposure of the local dashboard and ZTP/DHCP services you enable.

---

## 8. Children’s privacy

The App is intended for business / IT operators and is not directed to children under 13 (or the equivalent minimum age in your jurisdiction). We do not knowingly collect personal information from children.

---

## 9. International transfers

If you connect to Hayabusa Core, information may be processed on servers in the United States or other locations where we or our processors operate. Where required, we use appropriate safeguards for cross-border transfers.

---

## 10. Your choices and rights

Depending on your location, you may have rights to access, correct, delete, or restrict certain personal information, or to object to certain processing. To exercise these rights, contact [support@tracedroute.net](mailto:support@tracedroute.net).

You can also:

- Change or replace your local admin password in the App
- Disconnect or stop using cloud enrollment features where your deployment allows
- Disable ZTP/DHCP, robotics/radio features, or Integration Builder sync you do not want to use
- Uninstall or remove the App and delete local App data directories / volumes on the device

---

## 11. Microsoft Store

If you obtain the Windows App from the Microsoft Store, Microsoft’s own policies may also apply to Store account, download, and payment data, which we do not control. Linux distributions of the App are not delivered through the Microsoft Store.

Hosted copy for Store listing and public reference: [https://tracedroute.net/privacy.html](https://tracedroute.net/privacy.html)

---

## 12. Changes to this policy

We may update this Privacy Policy from time to time. The “Effective date” above will be revised when we do. Continued use of the App after an update means you acknowledge the revised policy.

---

## 13. Contact

**TracedRoute**  
Email: [support@tracedroute.net](mailto:support@tracedroute.net)  
Product support: [https://service.tracedroute.net/support/](https://service.tracedroute.net/support/)  
Website: [https://tracedroute.net](https://tracedroute.net)
