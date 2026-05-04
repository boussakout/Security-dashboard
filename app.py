import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from flask import Flask, jsonify, render_template
from db import init_db, get_events, get_stats

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/events')
def api_events():
    events = get_events(limit=100)
    result = []
    for row in events:
        result.append({
            "timestamp": row[0],
            "source":    row[1],
            "level":     row[2],
            "message":   row[3]
        })
    return jsonify(result)

@app.route('/api/stats')
def api_stats():
    stats = get_stats()
    result = {
        "CRITICAL": 0,
        "WARNING":  0,
        "INFO":     0
    }
    for row in stats:
        level = row[0]
        count = row[1]
        if level in result:
            result[level] = count
    return jsonify(result)

if __name__ == '__main__':
    init_db()
    print("🌐 Dashboard running at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
