# AI-Powered Cyber Threat Detector

An advanced security tool that uses machine learning to detect and analyze potential cyber threats in real-time.

## Features

- Real-time log scanning and analysis
- Phishing URL detection using VirusTotal API
- Login anomaly detection
- IP geo-location analysis
- Machine learning-based threat classification
- Web dashboard for monitoring and reporting
- Automated scheduled scans
- Real-time alerts

## Tech Stack

- **Backend**: Python with FastAPI
- **Database**: PostgreSQL
- **ML Libraries**: scikit-learn, XGBoost
- **Data Processing**: pandas
- **Visualization**: matplotlib, seaborn
- **Scheduling**: APScheduler
- **Authentication**: JWT tokens

## Project Structure

```
├── app/
│   ├── api/            # API endpoints
│   ├── core/           # Core functionality
│   ├── db/             # Database models and connections
│   ├── ml/             # Machine learning models
│   ├── schemas/        # Pydantic models
│   └── services/       # Business logic
├── tests/              # Test files
├── .env               # Environment variables
├── requirements.txt   # Project dependencies
└── README.md         # Project documentation
```

## Setup and Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ai-threat-detector.git
cd ai-threat-detector
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file with the following variables:
```
DATABASE_URL=postgresql://user:password@localhost:5432/threat_detector
VIRUSTOTAL_API_KEY=your_api_key
SECRET_KEY=your_secret_key
```

5. Initialize the database:
```bash
python -m app.db.init_db
```

6. Run the application:
```bash
uvicorn app.main:app --reload
```

## API Documentation

Once the application is running, visit `http://localhost:8000/docs` for the interactive API documentation.

## Security Features

- JWT-based authentication
- Password hashing
- Rate limiting
- Input validation
- Secure headers
- CORS protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 