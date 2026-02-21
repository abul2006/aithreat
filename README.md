# AI Insider Threat Detection System

A sophisticated machine learning-powered system for detecting insider threats using behavioral analytics and anomaly detection.

## Features

- **Real-time Threat Detection**: Uses Isolation Forest algorithm for anomaly detection
- **Behavioral Analytics**: Monitors user activity patterns and deviations
- **Interactive Dashboard**: Modern React-based UI with real-time updates
- **Threat Simulation**: Test different threat scenarios (data exfiltration, sabotage, etc.)
- **Risk Scoring**: AI-powered risk assessment with threat level classification
- **SQLite Database**: Persistent storage of activity logs and security alerts

## Architecture

- **Frontend**: React.js with Chart.js for data visualization
- **Backend**: Flask REST API with machine learning models
- **Database**: SQLite for data persistence
- **ML Engine**: Scikit-learn with Isolation Forest for anomaly detection

## Setup Instructions

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the backend server:**
   ```bash
   python backend.py
   ```
   The server will start on `http://127.0.0.1:5000`

3. **Open the frontend:**
   - Open `index.html` in your web browser
   - Or serve it using a local HTTP server

### Alternative: Using Python's built-in server
```bash
# In a new terminal, serve the frontend
python -m http.server 8000
# Then open http://localhost:8000 in your browser
```

## Usage

### Dashboard Features
- **Real-time Monitoring**: View current threat levels and alerts
- **Risk Metrics**: Critical, High, Medium, and Low risk alerts
- **User Risk Analysis**: Top risky users with activity counts
- **Activity Timeline**: 24-hour activity visualization

### Threat Simulation
Test different insider threat scenarios:
- **Normal Activity**: Baseline user behavior
- **Data Exfiltration**: Large data transfers, unusual access patterns
- **Insider Sabotage**: After-hours access, privilege escalation
- **Credential Misuse**: Suspicious login patterns

### API Endpoints
- `GET /dashboard` - Dashboard metrics and data
- `GET /alerts` - Security alerts with filtering
- `POST /simulate` - Simulate threat scenarios
- `POST /activity` - Log user activity

## Technical Details

### Machine Learning Model
- **Algorithm**: Isolation Forest (unsupervised anomaly detection)
- **Features**: Login time, file access patterns, data transfer volume, session duration, location, timing anomalies
- **Training**: Synthetic baseline data for normal user behavior
- **Risk Scoring**: 0-1 scale with threat level classification

### Security Features
- Real-time behavioral monitoring
- Automated alert generation
- Risk score calculation
- Threat level classification (CRITICAL, HIGH, MEDIUM, LOW)

## Project Structure
```
hackathon/
├── backend.py          # Flask server with ML engine
├── index.html          # React frontend dashboard
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── insider_threat.db  # SQLite database (created automatically)
```

## Troubleshooting

- **Port conflicts**: Change port in `backend.py` if 5000 is occupied
- **Dependencies**: Ensure all packages are installed via `pip install -r requirements.txt`
- **Database**: The SQLite database is created automatically on first run
- **CORS issues**: The backend includes CORS headers for local development

## Development

This is a demonstration system suitable for:
- Security research and education
- Proof-of-concept development
- Learning machine learning for cybersecurity
- Hackathon projects

## License

This project is for educational and demonstration purposes.
