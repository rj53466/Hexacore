# 🐧 HexaCore Linux Quick-Start Guide

Welcome! This guide will help you install and run **HexaCore** on any Linux machine (like Ubuntu, Debian, or Kali Linux). 

We have made this guide so simple that even a **10-year-old** can run it, but we also include all the details so you know exactly what is happening under the hood. Let's get started!

---

## ⚡ Option A: The "Super Easy" One-Click Way (Recommended)

If you want to install and run everything automatically using our master script, follow these 4 simple steps:

### 1. Open your Terminal
Open your Linux terminal app (usually by pressing `Ctrl + Alt + T`).

### 2. Get the project
If you don't already have the HexaCore folder on your machine, download it:
```bash
git clone https://github.com/rj53466/Hexacore.git
cd Hexacore
```
(Already have the folder? Just `cd` into it instead.)

### 3. Make the setup script executable
Run this command to allow the script to run:
```bash
chmod +x hexacore.sh
```

### 4. Run the setup script
Run this command to start the installation:
```bash
./hexacore.sh
```
* **What this does:** It checks if you have Python and Node.js installed, installs them if missing, downloads the security tools and the local AI model, builds the web console, and starts everything.
* **First time only:** this takes 15–30 minutes. Every run after that is instant — the same command just relaunches.

---

## 🛠️ Option B: The Step-by-Step Manual Way (Learn How It Works!)

If you want to run every command yourself and see exactly how it works, follow these steps:

### Step 1: Install System Software
We need **Python** (for the backend brain) and **Node.js/npm** (for the frontend screen).
Run this command to update and install them:
```bash
sudo apt-get update -y && sudo apt-get install -y python3 python3-pip python3-venv nodejs npm curl git
```
> [!NOTE]
> `sudo` runs the command with administrative privileges. You might be asked to type your Linux password.

---

### Step 2: Create a Clean Playground (Virtual Environment)
In Linux, it's best to install Python libraries in a separate, isolated playground (called a *virtual environment* or *venv*) so it doesn't mess up the rest of your computer.

1. **Create the environment:**
   ```bash
   python3 -m venv venv
   ```
2. **Step inside (Activate it):**
   ```bash
   source venv/bin/activate
   ```
   *(You will see `(venv)` appear at the very beginning of your terminal prompt!)*

---

### Step 3: Install the Backend Libraries
Now let's install the Python packages that run the API and logic:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
* **Why do we do this?** `requirements.txt` contains a list of packages (like `fastapi` and `uvicorn`) that the backend server uses to communicate.

---

### Step 4: Install the Frontend Libraries
Next, let's download the libraries for our web interface console:
```bash
cd console
npm install
cd ..
```
* **Why do we do this?** This downloads all the UI components, charts, and pages into a directory called `node_modules`.

---

### Step 5: Ingest the Skills Database
Our platform uses a corpus of security skills (`Heart/`). We need to compile them into an index:
```bash
python -m skillsvc.ingest --heart Heart
```
* **What happens?** The system reads the skill guidelines and prints a validation report!

---

### Step 6: Start the Engines!
You need to open two separate terminal tabs/windows, or run them in the background.

#### Terminal 1: Start the Backend API Server
```bash
python serve.py
```
* **Success Output:** You should see: `INFO: Uvicorn running on http://127.0.0.1:8000`

#### Terminal 2: Start the Frontend Console
*(Remember to open a new tab/window, navigate back to the project folder, and run:)*
```bash
cd console
npm run dev
```
* **Success Output:** You should see: `➜  Local:   http://localhost:5173/`

---

## 🌐 How to Access HexaCore

**If you used Option A** (`./hexacore.sh`), everything runs on one address — open your browser to:

* 🖥️ **Dashboard + API:** [http://localhost:8000/](http://localhost:8000/)
* ⚙️ **Backend API documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)

**If you used Option B** (the two manual terminals), the dashboard and API are on separate ports:

* 🖥️ **Dashboard (Frontend Console):** [http://localhost:5173/](http://localhost:5173/)
* ⚙️ **Backend API documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🔌 How to Stop the Servers

### If you used Option A (`./hexacore.sh`):
It runs right there in your terminal — press **`Ctrl + C`** in that same window to stop it.
(Or, once logged into the dashboard, click the **STOP** button in the top bar — owner login
required.)

### If you used Option B (Manual Setup):
In each terminal window where the server is running, press **`Ctrl + C`** on your keyboard to stop it!
