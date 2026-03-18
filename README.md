# 🌐 Custom NoSQL CMS & Portfolio Engine | Kalmai221

This repository contains a specialized **Python CMS** architected for serverless environments. It serves as my professional portfolio, demonstrating a full-stack integration of **Flask**, **MongoDB Atlas**, and **Vercel Serverless Functions**.

---

## 🚀 System Architecture

The core of this project is a dynamic routing engine that maps MongoDB documents to live web pages, wrapped in a robust DevOps pipeline.

* **Logic Layer:** Flask-based Serverless Backend (`/api/index.py`).
* **Data Layer:** MongoDB Atlas (NoSQL) for content, site settings, and real-time analytics.
* **Session Management:** Secure, hmac-signed trial environments for testing CMS features without persistent database writes.
* **DevOps:** Zero-config Continuous Deployment via **Vercel**, featuring automatic SSL and edge-optimized asset delivery.

| Component | Implementation |
| :--- | :--- |
| **Backend** | Python 3.10+ / Flask |
| **Database** | MongoDB Atlas (Cloud NoSQL) |
| **Authentication** | HMAC-signed sessions & Secure Decorators |
| **Deployment** | Vercel Serverless Functions (FaaS) |

---

## 📊 Engineering Highlights

### **Custom Analytics Engine**
Instead of relying on heavy third-party scripts, I built a custom analytics suite within the CMS. It utilizes **MongoDB Aggregation Pipelines** to process:
* **Real-time Traffic:** 5-minute window distinct IP tracking.
* **Geographic & Device Data:** User-Agent parsing for OS, Browser, and Device breakdown.
* **Traffic Sources:** Intelligent referrer filtering (Google, LinkedIn, GitHub, etc.).

### **Repurposed CMS Routing**
The application uses a "Catch-all" dynamic router (`cms_router`). It performs a three-tier check:
1.  **Global Maintenance:** System-wide lockout via MongoDB config.
2.  **Per-Page Maintenance:** Individual node status check.
3.  **Admin Bypass:** Secure session-based bypass for live editing.

### **Serverless Optimization**
To fit the Vercel architecture, the entire application (including `static` and `templates`) is encapsulated within the `/api` directory. This ensures that the Flask instance has direct relative access to UI components during the execution of stateless functions.

---

## 📁 Project Structure

```text
portfolio/
├── api/
│   ├── static/         # CSS, JS, and UI assets (Robots.txt, etc.)
│   ├── templates/      # Jinja2 HTML templates & Sitemap XML
│   └── index.py        # Core Flask Engine & CMS Logic
├── .env                # Environment Variables (SECRET_KEY, MONGO_URI)
├── requirements.txt    # dependencies (pymongo, certifi, user-agents)
└── README.md           # Documentation
```

---

## 🛠️ Local Setup

1.  **Clone & Install:**
    ```bash
    git clone [https://github.com/Kalmai221/portfolio.git](https://github.com/Kalmai221/portfolio.git)
    pip install -r requirements.txt
    ```
2.  **Config:** Create a `.env` with `MONGODB_URI` and `SECRET_KEY`.
3.  **Run:**
    ```bash
    python api/index.py
    ```

---

## 📫 Connect With Me

I’m always open to discussing **Python architecture**, **NoSQL data modeling**, or **Serverless DevOps**. Feel free to reach out via any of the platforms below:

* **Portfolio:** [klhportfolio.vercel.app](https://klhportfolio.vercel.app)
* **LinkedIn:** [linkedin.com/in/kurtishopewell](https://www.linkedin.com/in/kurtishopewell/)
* **GitHub:** [@Kalmai221](https://github.com/Kalmai221)

---
*Built with Python, MongoDB, and Love by Kalmai221*