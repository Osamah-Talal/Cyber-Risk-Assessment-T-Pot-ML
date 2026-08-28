# An Intelligent Cyber Risk Assessment Framework Using Real-World Honeypot Data, Behavioral Fingerprinting, and Machine Learning

**Bachelor's Capstone Graduation Project**  
**Department of Networks and Cybersecurity — Faculty of Engineering and Information Technology**  
**Al Janad University for Science and Technology | June 2026**

---

## 📌 Project Overview
Modern Security Operations Centers (SOCs) face alert fatigue caused by high volumes of security events. This project designs and implements an end-to-end framework to collect live threat intelligence, extract behavioral attack session patterns, and dynamically compute risk scores using machine learning and a rule-based engine.

### Core Objectives:
* **Honeypot Deployment:** Deployed the **T-Pot** multi-honeypot platform on **Microsoft Azure** to aggregate adversary interaction logs and capture live attack vectors.
* **Feature Engineering:** Extracted behavioral attributes from unstructured honeypot logs (session duration, command count, request frequency, port diversity).
* **Behavioral Fingerprinting:** Applied **K-Means clustering** to group similar attack sessions and generate behavioral attack fingerprints.
* **Risk Prioritization Engine:** Built a rule-based scoring engine to evaluate cluster metrics and categorize threats into **Low**, **Medium**, and **High** risk tiers to support SOC decision-making.

---

## 🏗 System Architecture & Workflow
