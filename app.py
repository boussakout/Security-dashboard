import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, jsonify, render_template, request
from db import init_db, get_events, get_stats

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/events')
def api_events():
    limit = request.args.get('limit', 1000, type=int)
    events = get_events(limit=limit)
    return jsonify([{
        "timestamp": row[0],
        "source":    row[1],
        "level":     row[2],
        "message":   row[3]
    } for row in events])

@app.route('/api/stats')
def api_stats():
    stats = get_stats()
    result = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for row in stats:
        if row[0] in result:
            result[row[0]] = row[1]
    return jsonify(result)

if __name__ == '__main__':
    init_db()
    print("🌐 Dashboard → http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
