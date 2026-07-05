# README.md
# AI Phishing Detector

A modern, AI-powered web application that analyzes emails, SMS messages, WhatsApp messages, and URLs to detect phishing attempts. Built with Flask, Google Gemini AI, and Bootstrap 5.

## Features

### Core Analysis
- **Text Analysis**: Analyze emails, SMS, or any text for phishing indicators
- **URL Analysis**: Examine URLs for suspicious patterns and domain spoofing
- **File Upload**: Upload TXT, CSV, or JSON files for analysis

### AI-Powered Detection
- 🔍 **Phishing Indicators**: Detect urgency language, credential requests, suspicious domains, and impersonation
- 📊 **Risk Score**: 0-100 risk assessment
- 🎯 **Threat Level**: Safe, Low, Medium, High, or Critical
- 💡 **AI Explanation**: Understand why content is flagged as dangerous
- 🛡️ **Security Recommendations**: Actionable advice for protection

### User Experience
- 🌓 **Dark/Light Mode**: Toggle between themes
- 📱 **Responsive Design**: Works on all devices
- ✨ **Glassmorphism UI**: Modern, aesthetic design
- 📋 **Copy Report**: One-click copy of analysis results
- 📄 **Export PDF**: Generate professional reports
- 📚 **History**: View previous analyses
- ⏳ **Loading Animation**: Visual feedback during AI processing

## Technology Stack

### Backend
- **Python 3.9+**
- **Flask**: Web framework
- **Google Gemini AI**: LLM for phishing detection
- **ReportLab**: PDF generation
- **python-dotenv**: Environment management

### Frontend
- **Bootstrap 5**: Responsive UI framework
- **Font Awesome 6**: Icons
- **Google Fonts (Inter)**: Typography
- **Vanilla JavaScript**: Client-side logic

## Installation

### Prerequisites
- Python 3.9 or higher
- Google Gemini API key

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ai-phishing-detector.git
cd ai-phishing-detector