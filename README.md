# ORBIT

Private link dashboard. Local only. No uplink.

Modules (callsign + URL) live in an encrypted vault on this device. There is no account and no server.

## Live

Anyone with the link: [https://simonemarzullo.github.io/orbit/](https://simonemarzullo.github.io/orbit/)

Each visitor’s username, password, and modules stay in their own browser. Nothing is stored on the server.

## Run locally

```bash
cd ~/Documents/AI/Grok/Orbit
python3 -m http.server 8787
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787).

## Add to Home Screen

**iPhone / iPad**
1. Open ORBIT in Safari
2. Share
3. Add to Home Screen
4. Add

**Desktop (Chrome / Edge)**
Use the install control in the address bar.

## Language

| Control | Meaning |
|---|---|
| ENTER | Unlock the deck |
| DECK | Your modules |
| NEW MODULE | Commit a link plate |
| SYSTEMS | Install, key, export, wipe |
| OPEN | Launch the URL |
| COMMIT | Save |
| ABORT | Cancel |
| RETIRE | Remove a plate |
| LOCK | Seal the vault |
| SCAN | Filter |

## Notes

- Username and password stay in the browser. A master key is wrapped with PBKDF2 + AES-GCM.
- Forgot password: Restore access + the restore key shown at first login.
- Change username/password or issue a new restore key under SYSTEMS.
- WIPE DECK destroys the vault on this device.
- EXPORT writes a JSON file of modules. Keep it private.
