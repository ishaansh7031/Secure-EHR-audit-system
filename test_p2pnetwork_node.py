#!/usr/bin/env python3
"""
test_p2pnetwork_node.py

Test harness for the new AuditServer/AuditNode system:
- Spins up an AuditServer writing to an SQLite DB in a temp directory
- Generates RSA key-pairs for server and auditor
- Appends several records to the audit store
- Instantiates an AuditNode for the auditor to fetch and decrypt those records
- Verifies that decrypted payloads match the original action_data
"""
import os
import tempfile
import unittest
from pathlib import Path

from Crypto.PublicKey import RSA

from AuditServer import AuditServer
from AuditNode import AuditNode

class AuditSystemTest(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for keys and DB
        self.tempdir = tempfile.TemporaryDirectory()
        base = Path(self.tempdir.name)
        keys_dir = base / 'keys'
        keys_dir.mkdir()

        # Generate server RSA key-pair
        server_key = RSA.generate(2048)
        self.server_priv = keys_dir / 'server_priv.pem'
        self.server_pub  = keys_dir / 'server_pub.pem'
        self.server_priv.write_bytes(server_key.export_key('PEM'))
        self.server_pub.write_bytes(server_key.publickey().export_key('PEM'))

        # Generate auditor RSA key-pair
        auditor_key = RSA.generate(2048)
        self.auditor_priv = keys_dir / 'auditor1_priv.pem'
        self.auditor_pub  = keys_dir / 'auditor1_pub.pem'
        self.auditor_priv.write_bytes(auditor_key.export_key('PEM'))
        self.auditor_pub.write_bytes(auditor_key.publickey().export_key('PEM'))

        # Paths
        self.audit_db = base / 'audit.db'
        notifier_cfg = {
            'name': 'test',
            'rate': 1,
            'identity': {'name': 'test', 'ip': '127.0.0.1', 'node_port': 0, 'server_port': 0}
        }

        # Instantiate AuditServer
        self.server = AuditServer(
            server_priv_path=str(self.server_priv),
            auditor_pub_paths={'auditor1': str(self.auditor_pub)},
            store_path=str(self.audit_db),
            notifier_config=notifier_cfg
        )

        # Instantiate AuditNode for auditor1
        self.node = AuditNode(
            node_id='auditor1',
            auditor_priv_path=str(self.auditor_priv),
            server_pub_path=str(self.server_pub),
            store_path=str(self.audit_db),
            notifier_config=notifier_cfg
        )

    def tearDown(self):
        # Stop server notifier and close its DB connection
        self.server.stop()
        # Stop node notifier threads
        self.node.notifier.stop()
        # Close node DB connection
        self.node.store.db.close()
        # Cleanup temp directory
        self.tempdir.cleanup()

    def test_append_and_retrieve(self):
        # Define a series of action_data payloads
        events = [
            {'event': 'LOGIN'},
            {'event': 'UPDATE_PROFILE'},
            {'event': 'LOGOUT'}
        ]
        # Append records
        for evt in events:
            success = self.server.append_user_record(user_id='user123', action_data=evt)
            self.assertTrue(success)

        # Fetch and decrypt via AuditNode
        decrypted = self.node.fetch_and_decrypt()
        # Should match number of events
        self.assertEqual(len(decrypted), len(events))
        # Each decrypted record includes the action_data under 'action'
        for dec, orig in zip(decrypted, events):
            self.assertEqual(dec['action'], orig)

if __name__ == '__main__':
    unittest.main()
