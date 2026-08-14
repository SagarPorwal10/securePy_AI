# 🔗 OLLAMA_CONNECT.md — Remote Ollama Connection Guide

This guide explains how to run Ollama on a **dedicated AI machine** (e.g. a desktop with a GPU) and connect SecurePy AI to it from any other PC on the same network.

---

## Overview

```
┌───────────────────────┐          LAN / Wi-Fi          ┌──────────────────────────┐
│   Your Laptop (SecurePy AI)  │ ──────────────────────► │   AI PC (Ollama server)  │
│   OLLAMA_HOST=192.168.1.50   │        port 11434        │   ollama serve           │
└───────────────────────┘                                └──────────────────────────┘
```

---

## Part 1 — Set Up the AI PC (the machine running Ollama)

### Step 1 — Install Ollama

Download and install from **https://ollama.com/download/windows** on the AI PC.

---

### Step 2 — Tell Ollama to listen on all network interfaces

By default, Ollama only listens on `127.0.0.1` (localhost). You need to change this so other machines can reach it.

**Option A — Set an environment variable before starting Ollama (recommended)**

Open PowerShell on the AI PC and run:

```powershell
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
```

> Keep this PowerShell window open while you use SecurePy AI.

**Option B — Set it permanently via Windows System Variables**

1. Press `Win + S` → search **"Edit the system environment variables"**
2. Click **Environment Variables…**
3. Under **User variables**, click **New**:
   - Variable name: `OLLAMA_HOST`
   - Variable value: `0.0.0.0`
4. Click **OK** → restart Ollama

---

### Step 3 — Pull the model on the AI PC

```powershell
# Lightweight (recommended to start):
ollama pull qwen2.5-coder:7b

# More powerful:
ollama pull codellama:13b
ollama pull deepseek-coder:6.7b
```

---

### Step 4 — Open the Windows Firewall on the AI PC

Ollama listens on port **11434**. You need to allow inbound connections to it.

```powershell
# Run this in an ADMINISTRATOR PowerShell on the AI PC:
New-NetFirewallRule `
    -DisplayName "Ollama API (SecurePy AI)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 11434 `
    -Action Allow
```

> ⚠️ **Only do this on a trusted private network.** Do NOT expose this port to the internet.

---

### Step 5 — Find the AI PC's IP address

```powershell
# Run this on the AI PC:
ipconfig
```

Look for the **IPv4 Address** under your active adapter (Wi-Fi or Ethernet), e.g.:

```
IPv4 Address . . . . . . . . . . : 192.168.1.50
```

Write this IP down — you'll need it on the other machine.

---

### Step 6 — Verify Ollama is reachable from the AI PC itself

```powershell
# Test that Ollama responds on all interfaces:
Invoke-RestMethod http://localhost:11434/api/tags
```

You should see a JSON list of models.

---

## Part 2 — Configure SecurePy AI (your laptop / scanning machine)

### Step 7 — Create your `.env` file

Copy the template and set the AI PC's IP:

```powershell
Copy-Item .env.example .env
```

Then open `.env` in any text editor and change `OLLAMA_HOST`:

```env
# .env
OLLAMA_HOST=192.168.1.50     # ← put the AI PC's IP here
OLLAMA_PORT=11434
OLLAMA_MODEL=qwen2.5-coder:7b
OLLAMA_TIMEOUT=180
OLLAMA_SCHEME=http
```

> The `.env` file is gitignored — it will never be committed.

---

### Step 8 — Test connectivity from your laptop

```powershell
# PowerShell equivalent of curl:
Invoke-RestMethod http://192.168.1.50:11434/api/tags
```

You should get a JSON response listing the models on the AI PC.

---

### Step 9 — Run SecurePy AI with the remote Ollama

Activate the virtual environment, then scan normally — it will automatically
read the `.env` file and connect to the remote machine:

```powershell
.venv\Scripts\Activate.ps1

# Uses settings from .env automatically:
python -m securepy_ai.cli scan examples/vulnerable.py --fix

# Or override the model on the fly:
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b
```

The CLI will print the resolved connection info before connecting:

```
Ollama Connection
  URL    : http://192.168.1.50:11434
  Model  : qwen2.5-coder:7b
  Timeout: 180s
  .env   : C:\...\securePy AI\.env
```

---

## Alternative — Use environment variables instead of a `.env` file

You can also set the variables directly in PowerShell without creating a file:

```powershell
$env:OLLAMA_HOST = "192.168.1.50"
$env:OLLAMA_MODEL = "qwen2.5-coder:7b"
python -m securepy_ai.cli scan examples/vulnerable.py --fix
```

Or pass the URL explicitly via CLI flag (overrides everything):

```powershell
python -m securepy_ai.cli scan examples/vulnerable.py `
    --fix `
    --ollama-url http://192.168.1.50:11434 `
    --model qwen2.5-coder:7b
```

---

## Config Priority Reference

| Priority | Method | Example |
|---|---|---|
| **1 (highest)** | `--ollama-url` CLI flag | `--ollama-url http://192.168.1.50:11434` |
| **2** | `--model` / `--timeout` CLI flags | `--model qwen2.5-coder:7b` |
| **3** | Environment variable | `$env:OLLAMA_HOST = "192.168.1.50"` |
| **4** | `.env` file | `OLLAMA_HOST=192.168.1.50` |
| **5 (lowest)** | Built-in default | `127.0.0.1:11434` |

---

## Troubleshooting

### ❌ `✗ Ollama is not reachable` — Remote host did not respond

| Check | Command (run on your laptop) |
|---|---|
| Is the AI PC on the network? | `ping 192.168.1.50` |
| Is port 11434 open? | `Test-NetConnection 192.168.1.50 -Port 11434` |
| Is Ollama running on the AI PC? | Check the AI PC — run `ollama serve` if not |
| Is the firewall rule applied? | Re-run the `New-NetFirewallRule` command above |

---

### ❌ `Ollama HTTP error 404`

The model you requested isn't pulled on the AI PC. Pull it there:

```powershell
ollama pull qwen2.5-coder:7b
```

---

### ❌ Request times out

Increase the timeout for large models:

```env
# .env
OLLAMA_TIMEOUT=300
```

Or via CLI:

```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --timeout 300
```

---

### 💡 Want to use mock mode while the AI PC is offline?

```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm
```

No Ollama connection is needed — great for testing the scanner pipeline.
