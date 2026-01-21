from flask import Flask, request, jsonify
from audit_server_core import AuditServer

app = Flask(__name__)

SERVER_PRIV_PATH = 'keys/server_priv.pem'
AUDITOR_PUB_PATHS = {
    "Auditor1": 'keys/auditor1_pub.pem'
}
AUDIT_DB_PATH = 'audit.db'
NOTIFIER_CONFIG = {
    'name': "Audit Server",
    'rate': 5,
    'identity': {
        'name': "Audit Server",
        'ip': "127.0.0.1",
        'node_port': 0,
        'server_port': 0
    }
}

server = AuditServer(SERVER_PRIV_PATH, AUDITOR_PUB_PATHS, AUDIT_DB_PATH, NOTIFIER_CONFIG)

@app.route('/append-record', methods=['POST'])
def append_record():
    content = request.json
    user_id = content.get('user_id')
    action_data = content.get('action_data')
    if not user_id or not action_data:
        return jsonify({"error": "Missing user_id or action_data"}), 400
    server.append_user_record(user_id, action_data)
    return jsonify({"status": "ok"}), 200

@app.route('/query-user/<user_id>', methods=['GET'])
def query_user(user_id):
    records = server.query_user(user_id)
    return jsonify(records), 200

@app.route('/query-user', methods=['GET'])
def query_all_users():
    records = server.query_user(None)
    return jsonify(records), 200

if __name__ == '__main__':
    app.run(port=6000)
