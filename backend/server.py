from flask import Flask, request, jsonify, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_PATH = "asm.db"

def init_db():
    """DB 초기화: scan_results 테이블 생성"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            version TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route("/report", methods=["POST"])
def receive_report():
    """
    클라이언트에서 POST로 받은 스캔 결과 JSON 배열을 DB에 저장
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "빈 데이터"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for item in data:
        c.execute('''
            INSERT INTO scan_results (ip, port, status, service, version, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            item.get('ip'),
            item.get('port'),
            item.get('status'),
            item.get('service', 'N/A'),
            item.get('version', 'N/A'),
            item.get('timestamp', datetime.now().isoformat())
        ))

    conn.commit()
    conn.close()
    return jsonify({"message": "결과 저장 완료"}), 200

@app.route("/results")
def show_results():
    """
    DB에서 최근 100건 스캔 결과를 조회하여
    HTML 테이블로 예쁘게 보여줌
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT ip, port, status, service, version, timestamp
        FROM scan_results
        ORDER BY timestamp DESC
        LIMIT 100
    ''')
    rows = c.fetchall()
    conn.close()

    html = '''
    <html>
    <head>
      <title>포트 스캔 결과</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: center; }
        th { background-color: #f4f4f4; }
        tr:nth-child(even) { background-color: #fafafa; }
      </style>
    </head>
    <body>
    <h1>포트 스캔 결과 (최신 100건)</h1>
    <table>
      <thead>
        <tr>
          <th>IP</th><th>Port</th><th>Status</th><th>Service</th><th>Version</th><th>Timestamp</th>
        </tr>
      </thead>
      <tbody>
      {% for row in rows %}
        <tr>
          <td>{{ row[0] }}</td>
          <td>{{ row[1] }}</td>
          <td>{{ row[2] }}</td>
          <td>{{ row[3] }}</td>
          <td>{{ row[4] }}</td>
          <td>{{ row[5] }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    </body>
    </html>
    '''

    return render_template_string(html, rows=rows)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
