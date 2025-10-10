# Secure Chat System

_(Python 3.11 + TypeScript)_

**Group Members:**

- a1894230 Yiyang Zhao – a1894230@adelaide.edu.au
- a1859543 Jiawei Hu
- a1875760 Ruilin Liu
- a18712370 Chenhao Zhao
- a1843864 Shengkang Shao

---

### 🔧 Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 🖥️ Backend Setup

```bash
python -m pip install -r requirements.txt
rm *.db
python -m backend.main --port 8765
```

### 🌐 Access

Open the browser and navigate to:  
**http://localhost:5173**

Use the interface to **register**, **log in**, and **enter the chat room**.

---

### 💬 Chat Room Interoperability Commands

| Command               | Description                      |
| --------------------- | -------------------------------- |
| `/list`               | List all connected users         |
| `/tell <user> <text>` | Send a private message           |
| `/all <text>`         | Broadcast a message to all users |
| `/file <user> <path>` | Send a file to a specific user   |

---

### 📝 Notes

1. **Test scripts** have been excluded from this peer-review version due to their large number. After multiple code revisions and architectural updates, many of the original tests are no longer runnable or aligned with the latest implementation.
2. **Inline comments** and **protocol-alignment annotations** were generated with AI assistance to enhance documentation consistency and traceability.
