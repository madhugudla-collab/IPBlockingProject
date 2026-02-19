# IP Blocking System with AI Threat Analysis

Automated IP blocking system that analyzes log files, identifies malicious IPs based on geolocation and reputation, and uses OpenAI GPT-4 for threat intelligence analysis with Phoenix observability.

## Features

- **IP Extraction**: Parses log files using regex to extract IPv4 addresses
- **Reputation Check**: Uses iplocate.io API to check:
  - Country of origin
  - Tor exit node status
  - Known abuser flag
- **Automatic Blocking**: Blocks IPs from:
  - High-risk countries (China, Russia, North Korea)
  - Tor exit nodes
  - Known abusers
- **AI Threat Analysis**: Uses OpenAI GPT-4o to analyze blocked IPs for:
  - Malware associations
  - Phishing campaigns
  - Command & Control (C2) activity
  - Risk scoring (0-100)
- **Phoenix Observability**: Real-time tracing and monitoring of OpenAI API calls

## Prerequisites

- Python 3.8 or higher
- OpenAI API key
- Internet connection for API calls

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/IPBlockingProject.git
cd IPBlockingProject
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `requests` - HTTP library for API calls
- `openai` - OpenAI Python SDK
- `python-dotenv` - Environment variable management
- `arize-phoenix` - Observability platform
- `openinference-instrumentation-openai` - OpenAI instrumentation

## Configuration

### Step 1: Get OpenAI API Key

1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in
3. Navigate to **API Keys** section
4. Click **Create new secret key**
5. Copy the key (starts with `sk-proj-...`)

### Step 2: Create .env File

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env
```

Edit `.env` and add your OpenAI API key:

```
OPENAI_API_KEY=sk-proj-your_actual_key_here
```

**⚠️ IMPORTANT:** Never commit `.env` file to Git. It's already in `.gitignore`.

### Step 3: Start Phoenix Server (Optional but Recommended)

Phoenix provides real-time observability for OpenAI API calls.

**Terminal 1 - Start Phoenix:**
```bash
python -m phoenix.server.main serve
```

This starts Phoenix at `http://localhost:6006`

**Open Phoenix UI:**
- Open browser: `http://localhost:6006`
- You'll see traces of all OpenAI API calls in real-time

## Usage

### Basic Usage

```bash
python LogfileReview.py test.log
```

### Multiple Log Files

```bash
python LogfileReview.py access.log error.log security.log
```

### Expected Output

```
API Status Code: 200
IP: 1.2.3.4, Country: China, TOR: False, Abuser: False
[BLOCKED] IP 1.2.3.4 (China) has been blocked.

Blocked IPs: {'1.2.3.4', '5.6.7.8'}
Blocked Details: [{'ip': '1.2.3.4', 'country': 'China', ...}]

=== AI Threat Analysis ===
============================================================
IP: 1.2.3.4
============================================================
Risk Score: 45
Malicious Type: Potential Suspicious Activity
Analysis:
This IP is located in China and has been flagged for...
```

## Log File Format

The script accepts standard Apache/Nginx log formats or any text file containing IP addresses:

```
192.168.1.1 - - [01/Jan/2024:12:00:00] "GET /index.html HTTP/1.1" 200 1234
[WARN] Failed login from 203.0.113.45
185.220.101.1 - - [01/Jan/2024:12:02:00] "POST /login HTTP/1.1" 401 0
```

## Blocking Rules

IPs are blocked if they match ANY of these criteria:

1. **Country-based**: IP from China, Russia, or North Korea
2. **Tor Exit Node**: IP identified as Tor exit node
3. **Known Abuser**: IP flagged by iplocate.io as known abuser

## Project Structure

```
IPBlockingProject/
├── LogfileReview.py      # Main script
├── test.log              # Sample log file
├── requirements.txt      # Python dependencies
├── .env                  # API keys (DO NOT COMMIT)
├── .env.example          # Template for .env
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## Troubleshooting

### Issue: ModuleNotFoundError

**Solution:**
```bash
# Ensure virtual environment is activated
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: OpenAI API Error 401 (Unauthorized)

**Solution:**
- Check `.env` file exists
- Verify `OPENAI_API_KEY` is correct
- Ensure no extra spaces or quotes around the key

### Issue: Rate Limit Errors from iplocate.io

**Solution:**
- Script includes 500ms delay between requests
- For large log files, consider using paid API tier

### Issue: Phoenix Not Starting

**Solution:**
```bash
# Install Phoenix separately
pip install arize-phoenix

# Start with explicit command
python -m phoenix.server.main serve --host 0.0.0.0 --port 6006
```

## API Costs

- **iplocate.io**: Free tier (1000 requests/day)
- **OpenAI GPT-4o**: ~$0.005 per blocked IP analyzed
  - Example: 100 blocked IPs = ~$0.50

## Security Notes

- Never commit `.env` file
- Keep OpenAI API key secure
- Review blocked IPs before implementing firewall rules
- Test with sample logs before production use

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

## License

MIT License - See LICENSE file for details

## Support

For issues or questions:
- Open GitHub Issue
- Check Phoenix docs: https://docs.arize.com/phoenix
- OpenAI API docs: https://platform.openai.com/docs

## Acknowledgments

- iplocate.io for IP reputation API
- OpenAI for GPT-4o threat analysis
- Arize Phoenix for observability platform
